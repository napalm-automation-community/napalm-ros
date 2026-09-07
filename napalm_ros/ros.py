"""NAPALM driver for MikroTik RouterBoard OS (ROS)"""

import re
import ssl
from collections import defaultdict
from itertools import chain

import librouteros.login
import napalm.base.constants as C
import napalm.base.utils.string_parsers
import paramiko
from librouteros import connect
from librouteros.exceptions import FatalError, MultiTrapError, TrapError
from librouteros.query import (
    And,
    Key,
)
from napalm.base import NetworkDriver
from napalm.base.exceptions import (
    CommitConfirmException,
    CommitError,
    ConnectionException,
    MergeConfigException,
    ReplaceConfigException,
)
from napalm.base.helpers import ip as cast_ip
from napalm.base.helpers import mac as cast_mac
from netaddr import IPAddress, IPNetwork
from netaddr.core import AddrFormatError
from packaging.version import parse as version_parse

from napalm_ros import (
    query,
    utils,
)

# Names of the on-device artifacts used for rollback. A backup taken before a plain
# commit lets rollback() restore the previous state; the commit-confirm job is a
# device-side scheduler that restores its own backup unless confirm_commit() cancels it.
ROLLBACK_SNAPSHOT = 'napalm-rollback'
REVERT_JOB = 'napalm-commit-confirm'


class ROSDriver(NetworkDriver):

    platform = 'ros'

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.optional_args = optional_args or {}
        self.version = None

        if self.optional_args.get('netbox_default_ssl_params', False):
            ctx = ssl.create_default_context()
            try:
                IPAddress(self.hostname)
                # IPAdresses cannot check hostname
                ctx.check_hostname = False
            except AddrFormatError:
                # if hostname is not IP, we use check_hostname variable
                ctx.check_hostname = self.optional_args.get('check_hostname', True)

            self.optional_args['ssl_wrapper'] = ctx.wrap_socket

        self.ssl_wrapper = self.optional_args.get('ssl_wrapper', librouteros.DEFAULTS['ssl_wrapper'])
        self.port = self.optional_args.get('port', 8729 if 'ssl_wrapper' in self.optional_args else 8728)
        self.ssh_port = self.optional_args.get('ssh_port', 22)
        self.paramiko_look_for_keys = self.optional_args.get('paramiko_look_for_keys', False)
        # paramiko's allow_agent default (True) is preserved so SSH key/agent auth keeps
        # working unchanged. If an SSH agent offers keys the device rejects, RouterOS can
        # drop the session and get_config then fails with "No existing session"; set
        # paramiko_allow_agent=False in optional_args to work around that.
        self.paramiko_allow_agent = self.optional_args.get('paramiko_allow_agent', True)
        self.api = None
        self.ssh = None
        # Buffered candidate configuration (set by load_*_candidate, applied by commit_config).
        self._candidate = None
        self._config_replace = False

    def close(self):
        if self.api is not None:
            self.api.close()
        if self.ssh is not None:
            self.ssh.close()

    def is_alive(self):
        '''No ping method is exposed from API'''
        return {'is_alive': True}

    def get_interfaces_counters(self):
        result = {}
        for iface in self.api('/interface/print', stats=True):
            result[iface['name']] = {
                'tx_errors': iface.get('tx-error', 0),
                'rx_errors': iface.get('rx-error', 0),
                'tx_discards': iface.get('tx-drop', 0),
                'rx_discards': iface.get('rx-drop', 0),
                'tx_octets': iface['tx-byte'],
                'rx_octets': iface['rx-byte'],
                'tx_unicast_packets': iface['tx-packet'],
                'rx_unicast_packets': iface['rx-packet'],
                'tx_multicast_packets': 0,
                'rx_multicast_packets': 0,
                'tx_broadcast_packets': 0,
                'rx_broadcast_packets': 0,
            }

        return result

    def get_bgp_neighbors(self):
        bgp_neighbors = defaultdict(lambda: {'peers': {}})
        sent_prefixes = defaultdict(lambda: defaultdict(int))

        # Count prefixes advertised to each configured peer
        for route in self.api("/routing/bgp/advertisements/print"):
            ip_version = IPNetwork(route["prefix"]).version
            sent_prefixes[route["peer"]][f"ipv{ip_version}"] += 1
        # Calculate stats for each routing BGP instance
        for inst in self.api("/routing/bgp/instance/print"):
            instance_name = "global" if inst["name"] == "default" else inst["name"]
            bgp_neighbors[instance_name]["router_id"] = inst["router-id"]
            inst_peers = find_rows(self.api("/routing/bgp/peer/print"), key="instance", value=inst["name"])
            for peer in inst_peers:
                prefix_stats = {}
                # MikroTik prefix counts are not per-AFI so attempt to query
                # the routing table if more than one address family is present on a peer
                if len(peer["address-families"].split(",")) > 1:
                    for af in peer["address-families"].split(","):
                        prefix_count = len(
                            self.api.path(f"/{af}/route").select(query.Keys.dst_addr).where(
                                query.Keys.bgp == True,
                                query.Keys.rcv_from == peer["name"],
                            )
                        )
                        family = "ipv4" if af == "ip" else af
                        prefix_stats[family] = {
                            "sent_prefixes": sent_prefixes.get(peer["name"], {}).get(family, 0),
                            "accepted_prefixes": prefix_count,
                            "received_prefixes": prefix_count,
                        }
                else:
                    family = "ipv4" if peer["address-families"] == "ip" else af
                    prefix_stats[family] = {
                        "sent_prefixes": sent_prefixes.get(peer["name"], {}).get(family, 0),
                        "accepted_prefixes": peer.get("prefix-count", 0),
                        "received_prefixes": peer.get("prefix-count", 0),
                    }
                bgp_neighbors[instance_name]["peers"][peer["remote-address"]] = {
                    "local_as": inst["as"],
                    "remote_as": peer["remote-as"],
                    "remote_id": peer.get("remote-id", ""),
                    "is_up": peer.get("established", False),
                    "is_enabled": not peer["disabled"],
                    "description": peer["name"],
                    "uptime": int(utils.parse_duration(peer.get("uptime", "0s")).total_seconds()),
                    "address_family": prefix_stats,
                }
        return dict(bgp_neighbors)

    def get_bgp_neighbors_detail(self, neighbor_address=""):
        peers = self.api.path("/routing/bgp/peer").select(*query.bgp_peers)
        if neighbor_address:
            peers.where(Key('remote-address') == neighbor_address)
        peers = tuple(peers)
        peer_names = {row['name'] for row in peers}
        peers_instances = {row['instance'] for row in peers}
        advertisements = self.api.path("/routing/bgp/advertisements").select(*query.bgp_advertisments)
        advertisements.where(Key('peer').In(*peer_names))
        advertisements = tuple(advertisements)
        instances = self.api.path('/routing/bgp/instance').select(*query.bgp_instances)
        instances.where(And(
            Key('name').In(*peers_instances),
            query.not_disabled,
        ))

        # Count prefixes advertised to each peer
        sent_prefixes = defaultdict(int)
        for route in advertisements:
            sent_prefixes[route["peer"]] += 1

        bgp_neighbors = defaultdict(lambda: defaultdict(list))
        for inst in instances:
            instance_name = "global" if inst["name"] == "default" else inst["name"]
            inst_peers = find_rows(peers, key="instance", value=inst["name"])

            for peer in inst_peers:
                peer_details = bgp_peer_detail(peer, inst, sent_prefixes)
                bgp_neighbors[instance_name][peer["remote-as"]].append(peer_details)

        return bgp_neighbors

    def get_arp_table(self, vrf=""):
        arp = self.api.path('/ip/arp').select(
            query.Keys.interface,
            query.Keys.mac_address,
            query.Keys.address,
        )
        if vrf:
            vrfs = self.api.path('/ip/route/vrf').select(query.Keys.interfaces).where(query.Keys.routing_mark == vrf)
            interfaces = flatten_split(vrfs, str(query.Keys.interfaces))
            arp.where(query.Keys.interface.In(*interfaces))
        return list(convert_arp_table(arp))

    def get_mac_address_table(self):
        table = []
        for entry in self.api('/interface/bridge/host/print'):
            table.append(
                {
                    'mac': entry['mac-address'],
                    'interface': entry['interface'],
                    'vlan': entry.get('vid', 1),  # Vlan id is not consistently set in the API
                    'static': not entry['dynamic'],
                    'active': not entry['invalid'],
                    'moves': 0,
                    'last_move': 0.0,
                }
            )

        try:
            for entry in self.api('/interface/ethernet/switch/unicast-fdb/print'):
                table.append(
                    {
                        'mac': entry['mac-address'],
                        'interface': entry['port'],
                        'vlan': entry['vlan-id'],
                        'static': not entry['dynamic'],
                        'active': entry['active'],
                        'moves': 0,
                        'last_move': 0.0,
                    }
                )
        except librouteros.exceptions.TrapError:
            # This only exists in the CRS1XX and CRS2XX switches.
            # Ignore if not present on the current device.
            pass

        return table

    def get_network_instances(self, name=""):
        query_ = self.api.path('/ip/route/vrf').select(
            query.Keys.interfaces,
            query.Keys.route_distinguisher,
            query.Keys.routing_mark,
        )
        if name:
            query_.where(query.Keys.routing_mark == name)
        return convert_vrf_table(query_)

    def get_lldp_neighbors(self):
        table = defaultdict(list)
        for entry in self.api.path('/ip/neighbor').select(
            query.Keys.identity,
            query.Keys.interface_name,
            query.Keys.interface,
        ):
            ifaces = LLDPInterfaces.fromApi(entry['interface'])
            table[ifaces.child].append({
                'hostname': entry['identity'],
                'port': entry.get('interface-name', ''),
            })
        return table

    def get_lldp_neighbors_detail(self, interface=""):
        table = defaultdict(list)
        for entry in self.api.path('/ip/neighbor').select(*query.lldp_neighbors):
            ifaces = LLDPInterfaces.fromApi(entry['interface'])
            table[ifaces.child].append(
                {
                    'parent_interface': ifaces.parent,
                    'remote_chassis_id': entry.get('mac-address', ''),
                    'remote_system_name': entry.get('identity', ''),
                    'remote_port': entry.get('interface-name', ''),
                    'remote_port_description': '',
                    'remote_system_description': entry.get('system-description', ''),
                    'remote_system_capab': entry.get('system-caps', '').split(','),
                    'remote_system_enable_capab': entry.get('system-caps-enabled', '').split(','),
                }
            )
        # There is no way of sending query for specific interface since parent and child
        # interface is embedded within one field on MikroTik
        if not interface:
            return table
        return table[interface]

    def get_ipv6_neighbors_table(self):
        ipv6_neighbors_table = []
        for entry in self.api('/ipv6/neighbor/print'):
            if 'mac-address' not in entry:
                continue
            ipv6_neighbors_table.append(
                {
                    'interface': entry['interface'],
                    'mac': cast_mac(entry['mac-address']),
                    'ip': cast_ip(entry['address']),
                    'age': float(-1),
                    'state': entry['status']
                }
            )
        return ipv6_neighbors_table

    def get_environment(self):
        environment = {
            'fans': {},
            'temperature': {},
            'power': {},
            'cpu': {},
            'memory': {
                'available_ram': 0,
                'used_ram': 0,
            },
        }

        try:
            system_resource = next(iter(self.api('/system/resource/print')))
        except StopIteration:
            return environment

        total_memory = system_resource.get('total-memory')
        free_memory = system_resource.get('free-memory')
        environment['memory'] = {'available_ram': total_memory, 'used_ram': int(total_memory - free_memory)}

        for entry in self.api('/system/health/print'):
            if 'temperature' in entry['name']:
                name = entry['name'].replace('-temperature', '')
                temperature = float(entry['value'])
                environment['temperature'][name] = {'temperature': temperature, 'is_alert': False, 'is_critical': False}
            elif 'speed' in entry['name']:
                name = entry['name'].replace('-speed', '')
                status = int(entry['value']) > 50
                environment['fans'][name] = {'status': status}
            elif 'state' in entry['name']:
                name = entry['name'].replace('-state', '')
                status = entry['value'] == 'ok'
                environment['power'][name] = {'status': status, 'capacity': 0.0, 'output': 0.0}

        for cpu_values in self.api('/system/resource/cpu/print'):
            name = cpu_values['cpu']
            environment['cpu'][name] = {'%usage': float(cpu_values['load'])}

        return environment

    def get_facts(self):
        resource = next(iter(self.api('/system/resource/print')))
        identity = next(iter(self.api('/system/identity/print')))
        routerboard = next(iter(self.api('/system/routerboard/print')))
        interfaces = tuple(self.api('/interface/print'))
        return {
            'uptime': float(utils.parse_duration(resource['uptime']).total_seconds()),
            'vendor': resource['platform'],
            'model': resource['board-name'],
            'hostname': identity['name'],
            'fqdn': '',
            'os_version': resource['version'],
            'serial_number': routerboard.get('serial-number', ''),
            'interface_list': napalm.base.utils.string_parsers.sorted_nicely(
                tuple(iface['name'] for iface in interfaces),
            ),
        }

    def get_config(self, retrieve='all', full=False, sanitized=False):
        configs = {'running': '', 'candidate': '', 'startup': ''}
        command = ["export", "terse"]
        version = next(iter(self.api('/system/package/update/print')))
        version = version_parse(version['installed-version'])
        if full:
            command.append("verbose")
        if version.major >= 7 and not sanitized:
            command.append("show-sensitive")
        if version.major <= 6 and sanitized:
            command.append("hide-sensitive")
        self.ssh.connect(
            self.hostname,
            port=self.ssh_port,
            username=self.username,
            password=self.password,
            look_for_keys=self.paramiko_look_for_keys,
            allow_agent=self.paramiko_allow_agent,
        )
        try:
            _, stdout, _ = self.ssh.exec_command(" ".join(command))
            config = stdout.read().decode().strip()
        finally:
            self.ssh.close()
        # remove date/time in 1st line
        config = re.sub(r"^# \S+ \S+ by (.+)$", r'# by \1', config, flags=re.MULTILINE)
        if retrieve in ("running", "all"):
            configs['running'] = config
        return configs

    # -- Configuration management (RouterOS 7.x, binary API only) --------------

    def load_merge_candidate(self, filename=None, config=None):
        self._candidate = self._read_candidate(filename, config)
        self._config_replace = False

    def load_replace_candidate(self, filename=None, config=None):
        self._candidate = self._read_candidate(filename, config)
        self._config_replace = True

    @staticmethod
    def _read_candidate(filename, config):
        # A filename takes precedence over an inline config string (NAPALM contract).
        if filename is not None:
            with open(filename, 'r', encoding='utf-8') as handle:
                return handle.read()
        return config or ''

    def compare_config(self):
        if self._candidate is None:
            return ''
        return self.api.config().compare(self._candidate)

    def discard_config(self):
        self._candidate = None
        self._config_replace = False

    def commit_config(self, message='', revert_in=None):
        if message:
            raise NotImplementedError('Commit message not implemented for this platform')
        if self._candidate is None:
            raise CommitError('No candidate configuration loaded.')
        # The NAPALM contract requires raising while a commit-confirm is still pending,
        # rather than re-arming (which would corrupt the rollback baseline) or leaving a
        # stale timer that later reboots the device.
        if self.has_pending_commit():
            raise CommitError('A commit confirm is already pending. Call confirm_commit or rollback first.')
        if revert_in is not None and self._config_replace:
            raise CommitConfirmException(
                'Commit confirm (revert_in) is not supported with a replace on RouterOS, '
                'because reset-configuration removes the scheduled rollback.'
            )
        cfg = self.api.config()
        error = ReplaceConfigException if self._config_replace else MergeConfigException
        try:
            # Snapshot the pre-change state so rollback() can always restore the last
            # commit. It must be persistent: a replace reboots, which would otherwise
            # discard a backup stored on the RAM disk.
            cfg.backup_save(ROLLBACK_SNAPSHOT, persistent=True)
            if revert_in is not None:
                # Device-side scheduler restores its backup unless confirm_commit() cancels it.
                cfg.arm_rollback(revert_in, name=REVERT_JOB)
        except (TrapError, MultiTrapError) as exc:
            raise CommitError(f'Failed to prepare rollback: {exc}')
        try:
            if self._config_replace:
                cfg.replace(self._candidate)
            else:
                cfg.apply(self._candidate)
        except (TrapError, MultiTrapError) as exc:
            raise error(str(exc))
        self._candidate = None

    def has_pending_commit(self):
        return self.api.config().rollback_pending(name=REVERT_JOB)

    def confirm_commit(self):
        self.api.config().cancel_rollback(name=REVERT_JOB)

    def rollback(self):
        cfg = self.api.config()
        # A pending commit-confirm is reverted by restoring its backup (this reboots the
        # device); otherwise restore the snapshot taken by the last plain commit. Both
        # backups are persistent (see commit_config).
        if cfg.rollback_pending(name=REVERT_JOB):
            cfg.backup_load(REVERT_JOB, persistent=True)
        elif cfg.backup_exists(ROLLBACK_SNAPSHOT, persistent=True):
            cfg.backup_load(ROLLBACK_SNAPSHOT, persistent=True)
        else:
            raise CommitError('No rollback snapshot available.')

    def get_interfaces(self):
        interfaces = {}
        for entry in self.api('/interface/print'):
            interfaces[entry['name']] = {
                'is_up': entry['running'],
                'is_enabled': not entry['disabled'],
                'description': entry.get('comment', ''),
                'last_flapped': -1.0,
                'mtu': entry.get('actual-mtu', 0),
                'speed': -1.0,
                'mac_address': cast_mac(entry['mac-address']) if entry.get('mac-address') else '',
            }
        return interfaces

    def get_interfaces_ip(self):
        interfaces_ip = {}

        ipv4_addresses = tuple(self.api('/ip/address/print'))
        for ifname in (row['interface'] for row in ipv4_addresses):
            interfaces_ip.setdefault(ifname, {})
            interfaces_ip[ifname]['ipv4'] = utils.iface_addresses(ipv4_addresses, ifname)

        try:
            ipv6_addresses = tuple(self.api('/ipv6/address/print'))
            for ifname in (row['interface'] for row in ipv6_addresses):
                interfaces_ip.setdefault(ifname, {})
                interfaces_ip[ifname]['ipv6'] = utils.iface_addresses(ipv6_addresses, ifname)
        except (TrapError, MultiTrapError):
            pass

        return interfaces_ip

    def get_ntp_servers(self):
        ntp_servers = {}
        ntp_client_values = next(iter(self.api('/system/ntp/client/print')))
        fqdn_ntp_servers = filter(None, ntp_client_values.get('server-dns-names', '').split(','))
        for ntp_peer in fqdn_ntp_servers:
            ntp_servers[ntp_peer] = {}
        primary_ntp = ntp_client_values.get('primary-ntp')
        secondary_ntp = ntp_client_values.get('secondary-ntp')
        if primary_ntp and primary_ntp != '0.0.0.0':
            ntp_servers[primary_ntp] = {}
        if secondary_ntp != '0.0.0.0':
            ntp_servers[secondary_ntp] = {}
        return ntp_servers

    def get_snmp_information(self):
        communities = {}
        for row in self.api('/snmp/community/print'):
            communities[row['name']] = {
                'acl': row.get('addresses', ''),
                'mode': 'ro' if row.get('read-access') else 'rw',
            }

        snmp_values = next(iter(self.api('/snmp/print')))

        return {
            'chassis_id': snmp_values['engine-id'],
            'community': communities,
            'contact': snmp_values['contact'],
            'location': snmp_values['location'],
        }

    def get_users(self):
        users = {}
        for row in self.api('/user/print'):
            users[row['name']] = {'level': 15 if row['group'] == 'full' else 0, 'password': '', 'sshkeys': []}
        return users

    def open(self):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        method = self.optional_args.get('login_method', 'plain')
        method = getattr(librouteros.login, method)
        try:
            self.api = connect(
                host=self.hostname,
                username=self.username,
                password=self.password,
                port=self.port,
                timeout=self.timeout,
                login_method=method,
                ssl_wrapper=self.ssl_wrapper,
            )
        except (TimeoutError, OSError, TrapError, FatalError, MultiTrapError) as exc:
            raise ConnectionException(f"Could not connect to {self.hostname}:{self.port} - [{exc!r}]")

    def ping(
        self,
        destination,
        source=C.PING_SOURCE,
        ttl=C.PING_TTL,
        timeout=C.PING_TIMEOUT,
        size=C.PING_SIZE,
        count=C.PING_COUNT,
        vrf=C.PING_VRF,
        source_interface=C.PING_SOURCE_INTERFACE,
    ):
        params = {
            'address': destination,
            'ttl': ttl,
            'size': size,
            'count': count,
        }
        if source:
            params['src-address'] = source
        if vrf:
            params['routing-table'] = vrf

        results = tuple(self.api('/ping', **params))
        ping_results = {
            'probes_sent': max(row['sent'] for row in results),
            'packet_loss': max(row['packet-loss'] for row in results),
            'rtt_min': utils.parse_duration(results[-1]['min-rtt']).total_seconds() * 1000,
            'rtt_max': utils.parse_duration(results[-1]['max-rtt']).total_seconds() * 1000,
            'rtt_avg': utils.parse_duration(results[-1]['avg-rtt']).total_seconds() * 1000,
            'rtt_stddev': float(-1),
            'results': []
        }

        for row in results:
            ping_results['results'].append(
                {
                    'ip_address': cast_ip(row['host']),
                    'rtt': utils.parse_duration(row['time']).total_seconds() * 1000,
                }
            )

        return {'success': ping_results}

    def get_vlans(self):
        result = {}
        for row in self.api('/interface/bridge/vlan/print'):
            for vid in row['vlan-ids'].split(','):
                untagged = filter(None, row['untagged'].split(','))
                tagged = filter(None, row['tagged'].split(','))
                ifs = set(chain(untagged, tagged))
                result[vid] = {
                    "name": "",
                    "interfaces": sorted(ifs),
                }
        return result


def find_rows(rows, key, value):
    """
    Yield each found row in which key == value.
    """
    for row in rows:
        if row.get(key) == value:
            yield row


def flatten_split(rows, key):
    """
    Iterate over given rows and split each found key by ','
    Returns unique split items.
    """
    items = (row[key].split(',') for row in rows)
    return set(chain.from_iterable(items))


def convert_arp_table(table):
    for entry in table:
        if 'mac-address' not in entry:
            continue

        yield {
            'interface': entry['interface'],
            'mac': cast_mac(entry['mac-address']),
            'ip': cast_ip(entry['address']),
            'age': float(-1),
        }


def convert_vrf_table(table):
    instances = {}
    for entry in table:
        ifaces = entry.get('interfaces').split(',')
        ifaces_dict = {iface: {} for iface in ifaces}
        instances[entry['routing-mark']] = {
            'name': entry['routing-mark'],
            'type': 'L3VRF',
            'state': {
                'route_distinguisher': entry.get('route-distinguisher')
            },
            'interfaces': {
                'interface': ifaces_dict
            },
        }
    return instances


class LLDPInterfaces:

    def __init__(self, parent, child):
        self.parent = parent
        self.child = child

    @staticmethod
    def fromApi(string):
        # interface names are the reversed interface e.g. sfp-sfpplus1,bridge will become bridge/sfp-sfpplus1
        if ',' in string:
            child, parent = string.split(',')
            return LLDPInterfaces(parent=parent, child=child)
        return LLDPInterfaces(parent='', child=string)


def bgp_peer_detail(peer, inst, sent_prefixes):
    return {
        "up": peer.get("established", False),
        "local_as": inst["as"],
        "remote_as": peer["remote-as"],
        "router_id": inst["router-id"],
        "local_address": peer.get("local-address", False),
        "local_address_configured": bool(peer.get("local-address", False)),
        "local_port": 179,
        "routing_table": inst["routing-table"],
        "remote_address": peer["remote-address"],
        "remote_port": 179,
        "multihop": peer["multihop"],
        "multipath": False,
        "remove_private_as": peer["remove-private-as"],
        "import_policy": peer["in-filter"],
        "export_policy": peer["out-filter"],
        "input_messages": peer.get("updates-received", 0) + peer.get("withdrawn-received", 0),
        "output_messages": peer.get("updates-sent", 0) + peer.get("withdrawn-sent", 0),
        "input_updates": peer.get("updates-received", 0),
        "output_updates": peer.get("updates-sent", 0),
        "messages_queued_out": 0,
        "connection_state": peer.get("state", ""),
        "previous_connection_state": "",
        "last_event": "",
        "suppress_4byte_as": not peer.get("as4-capability", True),
        "local_as_prepend": False,
        "holdtime": int(utils.parse_duration(peer.get("used-hold-time", peer.get("hold-time", "30s"))).total_seconds()),
        "configured_holdtime": int(utils.parse_duration(peer.get("hold-time", "30s")).total_seconds()),
        "keepalive": int(utils.parse_duration(peer.get("used-keepalive-time", "10s")).total_seconds()),
        "configured_keepalive": int(utils.parse_duration(peer.get("keepalive-time", "10s")).total_seconds()),
        "active_prefix_count": peer.get("prefix-count", 0),
        "received_prefix_count": peer.get("prefix-count", 0),
        "accepted_prefix_count": peer.get("prefix-count", 0),
        "suppressed_prefix_count": 0,
        "advertised_prefix_count": sent_prefixes.get(peer["name"], 0),
        "flap_count": 0,
    }
