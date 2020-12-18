"""NAPALM driver for Mikrotik RouterBoard OS (ROS)"""
from __future__ import unicode_literals

from collections import defaultdict
from itertools import chain
import socket

# Import third party libs
from librouteros import connect
from librouteros.exceptions import TrapError
from librouteros.exceptions import FatalError
from librouteros.exceptions import MultiTrapError
import librouteros.login
from librouteros.query import Key
from netaddr import IPNetwork

# Import NAPALM base
from napalm.base import NetworkDriver
import napalm.base.utils.string_parsers
import napalm.base.constants as C
from napalm.base.helpers import ip as cast_ip
from napalm.base.helpers import mac as cast_mac
from napalm.base.exceptions import ConnectionException

# Import local modules
from napalm_ros.utils import to_seconds
from napalm_ros.utils import iface_addresses


# pylint: disable=too-few-public-methods,undefined-variable
class Keys:
    bgp = Key('bgp')
    dst_addr = Key('dst-address')
    rcv_from = Key('received-from')
    mac_address = Key('max-address')
    interface = Key('interface')
    address = Key('address')


# pylint: disable=too-many-public-methods
class ROSDriver(NetworkDriver):

    # pylint: disable=super-init-not-called
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.optional_args = optional_args or dict()
        self.port = self.optional_args.get('port', 8728)
        self.api = None

    def close(self):
        self.api.close()

    def is_alive(self):
        '''No ping method is exposed from API'''
        return {'is_alive': True}

    def get_interfaces_counters(self):
        result = dict()
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

    # pylint: disable=invalid-name
    def get_bgp_neighbors(self):
        bgp_neighbors = defaultdict(lambda: dict(peers={}))
        sent_prefixes = defaultdict(lambda: defaultdict(int))

        # Count prefixes advertised to each configured peer
        for route in self.api("/routing/bgp/advertisements/print"):
            sent_prefixes[route["peer"]]["ipv{}".format(IPNetwork(route["prefix"]).version)] += 1
        # Calculate stats for each routing bgp instance
        for inst in self.api("/routing/bgp/instance/print"):
            instance_name = "global" if inst["name"] == "default" else inst["name"]
            bgp_neighbors[instance_name]["router_id"] = inst["router-id"]
            inst_peers = find_rows(self.api("/routing/bgp/peer/print"), key="instance", value=inst["name"])
            for peer in inst_peers:
                prefix_stats = {}
                # Mikrotik prefix counts are not per-AFI so attempt to query
                # the routing table if more than one address family is present on a peer
                if len(peer["address-families"].split(",")) > 1:
                    for af in peer["address-families"].split(","):
                        prefix_count = len(self.api.path(f"/{af}/route").select(dst_addr).where(
                            Keys.bgp == True, # pylint: disable=singleton-comparison
                            Keys.rcv_from == peer["name"],
                        ))
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
                    "uptime": to_seconds(peer.get("uptime", "0s")),
                    "address_family": prefix_stats,
                }
        return dict(bgp_neighbors)

    def get_bgp_neighbors_detail(self, neighbor_address=""):
        sent_prefixes = defaultdict(int)

        bgp_neighbors = defaultdict(lambda: defaultdict(list))
        # Get all configured peers
        peers = self.api("/routing/bgp/peer/print")
        # Get all configured advertisements
        advertisements = self.api("/routing/bgp/advertisements/print")
        # Count prefixes advertised to each configured peer
        for route in advertisements:
            sent_prefixes[route["peer"]] += 1

        for inst in self.api("/routing/bgp/instance/print"):
            instance_name = "global" if inst["name"] == "default" else inst["name"]
            inst_peers = find_rows(peers, key="instance", value=inst["name"])

            for peer in inst_peers:
                if neighbor_address and peer["remote-address"] != neighbor_address:
                    continue
                peer_details = {
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
                    "holdtime": to_seconds(peer.get("used-hold-time", peer.get("hold-time", "30s"))),
                    "configured_holdtime": to_seconds(peer.get("hold-time", "30s")),
                    "keepalive": to_seconds(peer.get("used-keepalive-time", "10s")),
                    "configured_keepalive": to_seconds(peer.get("keepalive-time", "10s")),
                    "active_prefix_count": peer.get("prefix-count", 0),
                    "received_prefix_count": peer.get("prefix-count", 0),
                    "accepted_prefix_count": peer.get("prefix-count", 0),
                    "suppressed_prefix_count": 0,
                    "advertised_prefix_count": sent_prefixes.get(peer["name"], 0),
                    "flap_count": 0,
                }
                bgp_neighbors[instance_name][peer["remote-as"]].append(peer_details)

        return {k: dict(v) for k, v in bgp_neighbors.items()}

    def get_arp_table(self, vrf=""):
        arp = self.api.path('/ip/arp')
        vrf_path = self.api.path('/ip/route/vrf')
        if vrf:
            vrfs = vrf_path.select(Keys.interface).where(Key('routing-mark') == vrf)
            interfaces = flatten_split(vrfs, 'interfaces')
            result = arp.select(
                Keys.interface,
                Keys.mac_address,
                Keys.address,
            ).where(Keys.interface.In(*interfaces))
            return list(convert_arp_table(result))
        else:
            return list(convert_arp_table(arp))

    def get_mac_address_table(self):
        table = list()
        for entry in self.api('/interface/bridge/host/print'):
            table.append(
                dict(
                    mac=entry['mac-address'],
                    interface=entry['interface'],
                    vlan=entry.get('vid', 1),     # The vid is not consistently set in the API
                    static=not entry['dynamic'],
                    active=not entry['invalid'],
                    moves=0,
                    last_move=0.0,
                )
            )

        try:
            for entry in self.api('/interface/ethernet/switch/unicast-fdb/print'):
                table.append(
                    dict(
                        mac=entry['mac-address'],
                        interface=entry['port'],
                        vlan=entry['vlan-id'],
                        static=not entry['dynamic'],
                        active=entry['active'],
                        moves=0,
                        last_move=0.0,
                    )
                )
        except librouteros.exceptions.TrapError:
            # This only exists in the CRS1XX and CRS2XX switches.
            # Ignore if not present on the current device.
            pass

        return table

    def get_network_instances(self, name=""):
        path = self.api.path('/ip/route/vrf')
        keys = ('interfaces', 'routing-mark', 'route-distinguisher')
        if name:
            query = path.select(*keys).where(Key('routing-mark') == name)
            return convert_vrf_table(query)
        return convert_vrf_table(path)

    @property
    def lldp(self):
        for entry in self.api('/ip/neighbor/print'):
            # interface names are the reversed interface e.g. sfp-sfpplus1,bridge will become bridge/sfp-sfpplus1
            entry['interface'] = '/'.join(entry['interface'].split(',')[::-1])
            yield entry

    def get_lldp_neighbors(self):
        table = defaultdict(list)
        for entry in self.lldp:
            table[entry['interface']].append(dict(
                hostname=entry['identity'],
                port=entry['interface-name'],
            ))
        return table

    def get_lldp_neighbors_detail(self, interface=""):
        table = defaultdict(list)
        for entry in self.lldp:
            table[entry['interface']].append(
                dict(
                    parent_interface=entry['interface'].split('/')[-1],
                    remote_chassis_id=entry.get('mac-address', ''),
                    remote_system_name=entry.get('identity', ''),
                    remote_port=entry.get('interface-name', ''),
                    remote_port_description='',
                    remote_system_description=entry.get('system-description', ''),
                    remote_system_capab=entry.get('system-caps', '').split(','),
                    remote_system_enable_capab=entry.get('system-caps-enabled', '').split(','),
                )
            )
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
            system_health = tuple(self.api('/system/health/print'))[0]
        except IndexError:
            return environment

        if system_health.get('active-fan', 'none') != 'none':
            environment['fans'][system_health['active-fan']] = {
                'status': int(system_health.get('fan-speed', '0RPM').replace('RPM', '')) != 0,
            }

        if 'temperature' in system_health:
            environment['temperature']['board'] = {
                'temperature': float(system_health['temperature']),
                'is_alert': False,
                'is_critical': False,
            }

        if 'cpu-temperature' in system_health:
            environment['temperature']['cpu'] = {
                'temperature': float(system_health['cpu-temperature']),
                'is_alert': False,
                'is_critical': False,
            }

        for cpu_values in self.api('/system/resource/cpu/print'):
            environment['cpu'][cpu_values['cpu']] = {
                '%usage': float(cpu_values['load']),
            }

        try:
            system_resource = tuple(self.api('/system/resource/print'))[0]
        except IndexError:
            return dict()

        total_memory = system_resource.get('total-memory')
        free_memory = system_resource.get('free-memory')
        environment['memory'] = {
            'available_ram': total_memory,
            'used_ram': int(total_memory - free_memory),
        }

        return environment

    def get_facts(self):
        resource = tuple(self.api('/system/resource/print'))[0]
        identity = tuple(self.api('/system/identity/print'))[0]
        routerboard = tuple(self.api('/system/routerboard/print'))[0]
        interfaces = tuple(self.api('/interface/print'))
        return {
            'uptime': to_seconds(resource['uptime']),
            'vendor': resource['platform'],
            'model': resource['board-name'],
            'hostname': identity['name'],
            'fqdn': u'',
            'os_version': resource['version'],
            'serial_number': routerboard.get('serial-number', ''),
            'interface_list': napalm.base.utils.string_parsers.sorted_nicely(
                tuple(iface['name'] for iface in interfaces),
            ),
        }

    def get_interfaces(self):
        interfaces = {}
        for entry in self.api('/interface/print'):
            interfaces[entry['name']] = {
                'is_up': entry['running'],
                'is_enabled': not entry['disabled'],
                'description': entry.get('comment', ''),
                'last_flapped': -1.0,
                'mtu': entry.get('actual-mtu', 0),
                'speed': -1,
                'mac_address': cast_mac(entry['mac-address']) if entry.get('mac-address') else u'',
            }
        return interfaces

    def get_interfaces_ip(self):
        interfaces_ip = {}

        ipv4_addresses = tuple(self.api('/ip/address/print'))
        for ifname in (row['interface'] for row in ipv4_addresses):
            interfaces_ip.setdefault(ifname, dict())
            interfaces_ip[ifname]['ipv4'] = iface_addresses(ipv4_addresses, ifname)

        try:
            ipv6_addresses = tuple(self.api('/ipv6/address/print'))
            for ifname in (row['interface'] for row in ipv6_addresses):
                interfaces_ip.setdefault(ifname, dict())
                interfaces_ip[ifname]['ipv6'] = iface_addresses(ipv6_addresses, ifname)
        except (TrapError, MultiTrapError):
            pass

        return interfaces_ip

    def get_ntp_servers(self):
        ntp_servers = {}
        ntp_client_values = tuple(self.api('/system/ntp/client/print'))[0]
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
                'acl': row.get('addresses', u''),
                'mode': u'ro' if row.get('read-access') else 'rw',
            }

        snmp_values = tuple(self.api('/snmp/print'))[0]

        return {
            'chassis_id': snmp_values['engine-id'],
            'community': communities,
            'contact': snmp_values['contact'],
            'location': snmp_values['location'],
        }

    def get_users(self):
        users = {}
        for row in self.api('/user/print'):
            users[row['name']] = {'level': 15 if row['group'] == 'full' else 0, 'password': u'', 'sshkeys': list()}
        return users

    def open(self):
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
            )
        except (TrapError, FatalError, socket.timeout, socket.error, MultiTrapError) as exc:
            # pylint: disable=raise-missing-from
            raise ConnectionException("Could not connect to {}:{} - [{!r}]".format(self.hostname, self.port, exc))

    # pylint: disable=too-many-arguments
    def ping(
        self,
        destination,
        source=C.PING_SOURCE,
        ttl=C.PING_TTL,
        timeout=C.PING_TIMEOUT,
        size=C.PING_SIZE,
        count=C.PING_COUNT,
        vrf=C.PING_VRF
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
        rtt = lambda x: (float(row.get(x, '-1ms').replace('ms', '')) for row in results)
        ping_results = {
            'probes_sent': max(row['sent'] for row in results),
            'packet_loss': max(row['packet-loss'] for row in results),
            'rtt_min': min(rtt('min-rtt')),
            'rtt_max': max(rtt('max-rtt')),                                         # Last result has calculated avg
            'rtt_avg': float(results[-1].get('avg-rtt', '-1ms').replace('ms', '')),
            'rtt_stddev': float(-1),
            'results': []
        }

        for row in results:
            ping_results['results'].append({
                'ip_address': cast_ip(row['host']),
                'rtt': float(row.get('time', '-1ms').replace('ms', '')),
            })

        return dict(success=ping_results)


def find_rows(rows, key, value):
    """
    Yield each found row in which key == value.
    """
    for row in rows:
        if row.get(key) == value:
            yield row


def flatten_split(rows, key):
    """
    Iterate over given rows and split each foun key by ','
    Returns unique splitted items.
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
    instances = dict()
    for entry in table:
        ifaces = entry.get('interfaces').split(',')
        ifaces_dict = dict((iface, dict()) for iface in ifaces)
        instances[entry['routing-mark']] = dict(
            name=entry['routing-mark'],
            type=u'L3VRF',
            state=dict(route_distinguisher=entry.get('route-distinguisher')),
            interfaces=dict(interface=ifaces_dict),
        )
    return instances
