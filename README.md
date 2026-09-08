[![PyPI](https://img.shields.io/pypi/v/napalm-ros.svg)](https://pypi.python.org/pypi/napalm-ros)
[![Supported python versions](https://img.shields.io/pypi/pyversions/napalm-ros.svg)](https://pypi.python.org/pypi/napalm-ros/)


### Caveats

As napalm-ros uses API, several caveats exist.

* API is not versioned so things may break when routeros is upgraded.
* RouterOS has no native, non-reboot commit/rollback and safe mode is not exposed via the API. Rollback is emulated with a device-side scheduler that restores a backup, so a rollback (or an expired commit-confirm) reverts by rebooting. See Configuration management.
* `get_config` reads the running configuration over the binary API on RouterOS 7 (no SSH). On RouterOS 6 it falls back to SSH (paramiko), where paramiko offers keys from a running SSH agent by default; if the agent offers a key the device rejects, RouterOS may drop the session and `get_config` then fails with `No existing session`. Pass `optional_args={'paramiko_allow_agent': False}` to authenticate with the password only (SSH agent/key auth is otherwise left enabled); `paramiko_look_for_keys` (default `False`) similarly controls on-disk key lookup.


### Configuration management

Configuration management is supported on **RouterOS 7.x** and is implemented entirely over the binary API (via `librouteros`), so it needs no SSH access.

* `get_config` / `compare_config` read the running configuration with `/export`.
* `load_merge_candidate` stages a `.rsc` script that is applied with `/import`. `load_replace_candidate` stages a full configuration.
* `commit_config` applies the candidate. Before a plain commit a backup is taken so `rollback` can restore it (by rebooting). `commit_config(revert_in=<seconds>)` arms a device-side scheduler that restores that backup unless `confirm_commit` is called in time (`has_pending_commit` reports whether one is armed). Because the timer lives on the device it survives a lost session or a lock-out.
* A replace (`load_replace_candidate` + `commit_config`) uses `/system reset-configuration run-after-reset`, which wipes the configuration and reboots into the candidate. It is destructive, has no automatic rollback, and the candidate must be a complete, self-consistent configuration that restores management connectivity. Commit-confirm (`revert_in`) is not available with a replace.

RouterOS configuration is imperative (an `/export` is a list of `add`/`set` actions, not declarative state) and ordering matters in some paths (e.g. `/ip firewall filter`) but not others (e.g. `/ip address`). `compare_config` is therefore a textual diff for review, not an executable patch.


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
* get_bgp_neighbors
* get_bgp_neighbors_detail
* get_config
* get_vlans
