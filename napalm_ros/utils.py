from datetime import timedelta

from napalm.base.helpers import (
    ip as cast_ip,
)


def parse_duration(duration_str: str):
    tdmap = {
        'w': 'weeks',
        'd': 'days',
        'h': 'hours',
        'm': 'minutes',
        's': 'seconds',
        'ms': 'milliseconds',
        'us': 'microseconds',
    }
    tdargs = dict()
    nums = ''
    unit = ''
    for char in duration_str:
        if char.isdigit() and not unit:
            nums += char
        elif char.isalpha() and nums:
            unit += char
        elif char.isdigit() and unit:
            tdargs[tdmap[unit]] = int(nums)
            nums = char
            unit = ''
    tdargs[tdmap[unit]] = int(nums)
    return timedelta(**tdargs)


def iface_addresses(rows, ifname):
    '''
    Return every found address and prefix length for given interface.

    example:
        {
        '192.168.1.1':
            {'prefix_length': 24}
        }
    '''
    found = (row['address'].split('/', 1) for row in rows if row['interface'] == ifname)
    pairs = ((cast_ip(address), int(prefix_length)) for address, prefix_length in found)
    return dict((address, dict(prefix_length=length)) for address, length in pairs)
