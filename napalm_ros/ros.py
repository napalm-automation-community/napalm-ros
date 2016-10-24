"""NAPALM driver for Mikrotik RouterBoard OS (ROS)"""

from napalm_base.base import NetworkDriver


class ROSDriver(NetworkDriver):
    """
    RouterOS NAPALM driver using Mikrotik API.

    Mikrotik does not expose 'safe mode' via API and there is
    no way of issuing any kind of commit/rollback.
    """

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        optional_args = optional_args or {}
        self.port = optional_args.get('port', 22)
        self.ros_version = None
        self.candidate_config = dict()

    def cli(self, *commands):
        pass

    def close(self):
        pass

    def open(self):
        pass

    def commit_config(self):
        pass

    def discard_config(self):
        self.candidate_config = dict()

    def get_arp_table(self):
        # {
        #     'interface': unicode(arp_entry.get('interface')),
        #     'mac': napalm_base.helpers.mac(arp_entry.get('mac-address')),
        #     'ip': napalm_base.helpers.ip(arp_entry.get('address')),
        #     'age': float(-1),
        # }
        pass

    def get_config(self):
        pass

    def get_facts(self):
        # return {
        #     'uptime': ros_utils.to_seconds(system_resource['uptime']),
        #     'vendor': unicode(system_resource['platform']),
        #     'model': unicode(system_resource['board-name']),
        #     'hostname': unicode(system_identity['name']),
        #     'fqdn': u'',
        #     'os_version': unicode(system_resource['version']),
        #     'serial_number': unicode(system_routerboard.get('serial-number', '')),
        #     'interface_list': napalm_base.utils.string_parsers.sorted_nicely(
        #         [intf.get('name') for intf in self._api_get('/interface')]
        #     ),
        # }
        pass
