"""NAPALM driver for Mikrotik RouterBoard OS (ROS)"""
from __future__ import unicode_literals

from collections import defaultdict

# Import third party libs
from librouteros import connect
from librouteros.exceptions import TrapError
from librouteros.exceptions import FatalError
from librouteros.exceptions import ConnectionError
from librouteros.exceptions import MultiTrapError
import librouteros.login

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


class ROSDriver(NetworkDriver):

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        optional_args = optional_args or dict()
        self._process_optional_args(optional_args)
        self.port = optional_args.get('port', 8728)
        self.api = None

    def _process_optional_args(self, optional_args={}):
        self.login_methods = tuple(
            set(
                [
                    getattr(librouteros.login, method, "login_plain")
                    for method in optional_args.get("login_methods", ["login_token", "login_plain"])
                ]
            )
        )

    def close(self):
        self.api.close()

    def is_alive(self):
        '''No ping method is exposed from API'''
        return {'is_alive': True}

    def get_interfaces_counters(self):
        result = dict()
        for iface in self.api('/interface/print', stats=True):
            result[iface['name']] = defaultdict(int)
            stats = result[iface['name']]
            stats['tx_errors'] += iface['tx-error']
            stats['rx_errors'] += iface['rx-error']
            stats['tx_discards'] += iface['tx-drop']
            stats['rx_discards'] += iface['rx-drop']
            stats['tx_octets'] += iface['tx-byte']
            stats['rx_octets'] += iface['rx-byte']
            stats['tx_unicast_packets'] += iface['tx-packet']
            stats['rx_unicast_packets'] += iface['rx-packet']
            # Stats below can not be read from /interface submenu
            stats['tx_multicast_packets'] += 0
            stats['rx_multicast_packets'] += 0
            stats['tx_broadcast_packets'] += 0
            stats['rx_broadcast_packets'] += 0

        return result

    def get_arp_table(self, vrf=""):
        if vrf:
            vrfs = self.api('/ip/route/vrf/print')
            vrfs = find(vrfs, key='routing-mark', value=vrf)
            interfaces = tuple(splitKey(vrfs, 'interfaces'))
            arp_table = list(entry for entry in self.arp if entry['interface'] in interfaces)
        else:
            arp_table = list(self.arp)

        return arp_table

    def get_mac_address_table(self):
        table = list()
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
        return table

    def get_network_instances(self, name=""):
        instances = dict()
        for inst in self.api('/ip/route/vrf/print'):
            ifaces = inst.get('interfaces').split(',')
            ifaces_dict = dict((iface, dict()) for iface in ifaces)
            instances[inst['routing-mark']] = dict(
                name=inst['routing-mark'],
                type=u'L3VRF',
                state=dict(route_distinguisher=inst.get('route-distinguisher')),
                interfaces=dict(interface=ifaces_dict),
            )
        if not name:
            return instances
        return instances[name]

    def get_lldp_neighbors(self):
        table = dict()
        for entry in self.api('/ip/neighbor/print'):
            # interface names are the reversed interface e.g. sfp-sfpplus1,bridge will become bridge/sfp-sfpplus1
            interface_name = '/'.join(entry['interface'].split(',')[::-1])

            table.setdefault(interface_name, list())
            table[interface_name].append(dict(
                hostname=entry['identity'],
                port=entry['interface-name'],
            ))
        return table

    def get_lldp_neighbors_detail(self, interface=""):
        table = dict()
        for entry in self.api('/ip/neighbor/print'):
            # interface names are the reversed interface e.g. sfp-sfpplus1,bridge will become bridge/sfp-sfpplus1
            interface_name = '/'.join(entry['interface'].split(',')[::-1])
            # we define the last part of the interface name as parent interface
            parent_interface = interface_name.split('/')[-1]

            table.setdefault(interface_name, list())
            table[interface_name].append(
                dict(
                    parent_interface=parent_interface,
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

    @property
    def arp(self):
        for entry in self.api('/ip/arp/print'):
            if 'mac-address' not in entry:
                continue
            else:
                yield {
                    'interface': entry['interface'],
                    'mac': cast_mac(entry['mac-address']),
                    'ip': cast_ip(entry['address']),
                    'age': float(-1),
                }

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
            'memory': {},
        }

        system_health = self.api('/system/health/print')[0]

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

        system_resource = self.api('/system/resource/print')[0]

        total_memory = system_resource.get('total-memory')
        free_memory = system_resource.get('free-memory')
        environment['memory'] = {
            'available_ram': total_memory,
            'used_ram': int(total_memory - free_memory),
        }

        return environment

    def get_facts(self):
        resource = self.api('/system/resource/print')[0]
        identity = self.api('/system/identity/print')[0]
        routerboard = self.api('/system/routerboard/print')[0]
        interfaces = self.api('/interface/print')
        return {
            'uptime': to_seconds(resource['uptime']),
            'vendor': resource['platform'],
            'model': resource['board-name'],
            'hostname': identity['name'],
            'fqdn': u'',
            'os_version': resource['version'],
            'serial_number': routerboard.get('serial-number', ''),
            'interface_list': napalm.base.utils.string_parsers.sorted_nicely(tuple(iface['name'] for iface in interfaces)),
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

        ipv4_addresses = self.api('/ip/address/print')
        for ifname in (row['interface'] for row in ipv4_addresses):
            interfaces_ip.setdefault(ifname, dict())
            interfaces_ip[ifname]['ipv4'] = iface_addresses(ipv4_addresses, ifname)

        try:
            ipv6_addresses = self.api('/ipv6/address/print')
            for ifname in (row['interface'] for row in ipv6_addresses):
                interfaces_ip.setdefault(ifname, dict())
                interfaces_ip[ifname]['ipv6'] = iface_addresses(ipv6_addresses, ifname)
        except (TrapError, MultiTrapError):
            pass

        return interfaces_ip

    def get_ntp_servers(self):
        ntp_servers = {}
        ntp_client_values = self.api('/system/ntp/client/print')[0]
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

        snmp_values = self.api('/snmp/print')[0]

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
        try:
            self.api = connect(
                host=self.hostname,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                login_methods=self.login_methods,
            )
        except (TrapError, FatalError, ConnectionError, MultiTrapError) as exc:
            raise ConnectionException("Could not connect to {}:{} - [{!r}]".format(self.hostname, self.port, exc))

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
            'count': count,
            'address': destination,
            'ttl': ttl,
            'size': size,
            'count': count,
        }
        if source:
            params['src-address'] = source
        if vrf:
            params['routing-table'] = vrf

        results = self.api('/ping', **params)

        ping_results = {
            'probes_sent': max(row['sent'] for row in results),
            'packet_loss': max(row['packet-loss'] for row in results),
            'rtt_min': min(float(row.get('min-rtt', '-1ms').replace('ms', '')) for row in results),
            'rtt_max': max(float(row.get('max-rtt', '-1ms').replace('ms', '')) for row in results), # Last result has calculated avg
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

    def _system_package_enabled(self, package):
        enabled = (pkg['name'] for pkg in self.api('/system/package/print') if not pkg['disabled'])
        return package in enabled


def find(haystack, key, value):
    for row in haystack:
        if row.get(key) == value:
            yield row


def splitKey(haystack, key):
    for row in haystack:
        for item in row[key].split(','):
            yield item
