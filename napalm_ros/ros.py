"""NAPALM driver for Mikrotik RouterBoard OS (ROS)"""

from napalm_base.base import NetworkDriver
from rosapi import connect


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
        self.port = optional_args.get('port', 8728)
        self.api = None

    def close(self):
        self.api.close()

    def open(self):
        self.api = connect(
                host=self.hostname,
                username=self.username,
                password=self.password,
                port=self.port,
                timeout=self.timeout
                )

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
            'serial_number': routerboard.get('serial_number', ''),
            'interface_list': tuple(iface['name'] for iface in interfaces)
        }


def to_seconds(time_format):
    """
    Convert time in human readable form to seconds.

    :param str time_format: Time format eg. 1h22m13s
    :returns: Converted time in seconds
    :rtype: int
    """
    seconds = minutes = hours = days = weeks = 0

    number_buffer = ''
    for current_character in time_format:
        if current_character.isdigit():
            number_buffer += current_character
            continue
        if current_character == 's':
            seconds = int(number_buffer)
        elif current_character == 'm':
            minutes = int(number_buffer)
        elif current_character == 'h':
            hours = int(number_buffer)
        elif current_character == 'd':
            days = int(number_buffer)
        elif current_character == 'w':
            weeks = int(number_buffer)
        else:
            raise ValueError('Invalid specifier - [{}]'.format(current_character))
        number_buffer = ''

    seconds += (minutes * 60)
    seconds += (hours * 3600)
    seconds += (days * 86400)
    seconds += (weeks * 604800)

    return seconds
