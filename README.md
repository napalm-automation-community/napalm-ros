[![Build Status](https://travis-ci.org/napalm-automation-community/napalm-ros.svg?branch=develop)](https://travis-ci.org/napalm-automation-community/napalm-ros)
[![PyPI](https://img.shields.io/pypi/v/napalm-ros.svg)](https://pypi.python.org/pypi/napalm-ros)
[![Supported python versions](https://img.shields.io/pypi/pyversions/napalm-ros.svg)](https://pypi.python.org/pypi/napalm-ros/)


### Caveats

As napalm-ros uses API, several caveats exist.

* No safe mode (not exposed via API). There is no commit, rollback.
* API is not versioned so things may break when routeros is upgraded.


### Missing features.

This driver does not implement any configuration management. Config management on mikrotik is different than on cisco, juniper etc. which provide
`config replace`. You provide a plain text config file and replace running config with that. MikroTik does not have this. Some menu paths (eg. /ip
address) do not have any order in which entries appear. Only one unique ip address can exist within a VRF. In some paths (eg. /ip firewall filter)
order matter.


### Implemented getters

* get_arp_table
* get_interfaces_counters
* get_environment
* get_facts
* get_interfaces
* get_interfaces_ip
* get_ntp_servers
* get_snmp_information
* get_users
* get_ipv6_neighbors_table
* is_alive
* ping
* get_lldp_neighbors
* get_lldp_neighbors_detail
* get_network_instances
* get_mac_address_table
