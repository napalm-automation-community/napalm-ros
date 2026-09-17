[![PyPI](https://img.shields.io/pypi/v/napalm-ros.svg)](https://pypi.python.org/pypi/napalm-ros)
[![Supported python versions](https://img.shields.io/pypi/pyversions/napalm-ros.svg)](https://pypi.python.org/pypi/napalm-ros/)


### Caveats

As napalm-ros uses API, several caveats exist.

* API is not versioned so things may break when routeros is upgraded.
* RouterOS has no native, non-reboot commit/rollback and safe mode is not exposed via the API. Rollback is emulated with a device-side scheduler that restores a backup, so a rollback (or an expired commit-confirm) reverts by rebooting. See Configuration management.
* `get_config` reads the running configuration over the binary API on **RouterOS 7.13+** (no SSH). Below 7.13 -- RouterOS 6 and RouterOS 7.0-7.12 -- it falls back to SSH (paramiko), because reading a large export back over the API needs the chunked `/file/read` added in 7.13. On that SSH path, paramiko offers keys from a running SSH agent by default; if the agent offers a key the device rejects, RouterOS may drop the session and `get_config` then fails with `No existing session`. Pass `optional_args={'paramiko_allow_agent': False}` to authenticate with the password only (SSH agent/key auth is otherwise left enabled); `paramiko_look_for_keys` (default `False`) similarly controls on-disk key lookup.


### Configuration management

Configuration management targets **RouterOS 7.x** and requires **librouteros >= 4.2.2**, which carries the `/file/add` fix `commit_config` relies on to apply a candidate on RouterOS older than ~7.13.

The commit/rollback machinery -- `load_merge_candidate` / `load_replace_candidate`, `commit_config`, `confirm_commit`, `has_pending_commit`, `rollback`, `discard_config` -- runs **entirely over the binary API** (no SSH). `get_config` and `compare_config` read the running configuration the version-aware way noted above: binary API on RouterOS 7.13+, SSH (paramiko) fallback below 7.13.

* `get_config` / `compare_config` read the running configuration with `/export`.
* `load_merge_candidate` stages a `.rsc` script that is applied with `/import`. `load_replace_candidate` stages a full configuration.
* `commit_config` applies the candidate. On **RouterOS 7.16+** it first dry-runs the candidate (`/import dry-run`) so a syntax error is caught before anything is applied; below 7.16 that pre-flight is skipped (pass `optional_args={'validate_before_commit': False}` to disable it). Before a plain commit a backup is taken so `rollback` can restore it (by rebooting). `commit_config(revert_in=<seconds>)` arms a device-side scheduler that restores that backup unless `confirm_commit` is called in time (`has_pending_commit` reports whether one is armed). Because the timer lives on the device it survives a lost session or a lock-out.
* A replace (`load_replace_candidate` + `commit_config`) uses `/system reset-configuration run-after-reset`, which wipes the configuration and reboots into the candidate. It is destructive, has no automatic rollback, and the candidate must be a complete, self-consistent configuration that restores management connectivity. Commit-confirm (`revert_in`) is not available with a replace.

RouterOS configuration is imperative (an `/export` is a list of `add`/`set` actions, not declarative state) and ordering matters in some paths (e.g. `/ip firewall filter`) but not others (e.g. `/ip address`). `compare_config` is therefore a textual diff for review, not an executable patch.


### cli

`cli(commands)` runs each command as a one-line script with `/execute` over the binary API (no SSH) and returns what it printed, keyed by command. Commands are RouterOS script syntax, not interactive-terminal shorthand (abbreviated menu names, tab completion): `/ip/address/print` or `:put [/system/identity/get name]` on RouterOS 7, `/ip address print` on RouterOS 6 (which does not accept the slash-separated form). A command RouterOS cannot parse comes back as output text (`syntax error (line 1 column 6)`), the way an IOS `% Invalid input` would, not as an exception. Only the `text` encoding is supported.

* On **RouterOS 7** (verified on 7.18.2 and 7.23.5) `/execute as-string` blocks and returns the output directly. RouterOS caps an executed script at 64 KB.
* **RouterOS 6** rejects `as-string` (verified on 6.33.3, 6.44.5, 6.49.21), so there the script runs as a background job writing to a temporary file (`napalm-cli-<id>.txt`), which is read back and removed. The API only exposes a file's contents inline when it is under about 4 KB and RouterOS 6 has no `/file/read`, so larger output raises `CommandErrorException`; use SSH for that. Support is detected on the first `cli()` call of a session, not from the version number.

Line endings are normalised to `\n`.


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
* cli
