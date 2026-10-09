from librouteros.query import Key

# pylint: disable=singleton-comparison
not_disabled = Key('disabled') == False


# pylint: disable=too-few-public-methods
class Keys:
    address = Key('address')
    address_families = Key("address-families")
    as4_capability = Key("as4-capability")
    as_num = Key("as")
    as_override = Key("as_override")
    bgp = Key('bgp')
    client_to_client_reflection = Key("client-to-client-reflection")
    default = Key("default")
    default_originate = Key("default-originate")
    disabled = Key("disabled")
    dst_addr = Key('dst-address')
    established = Key("established")
    hold_time = Key("hold-time")
    identity = Key('identity')
    ignore_as_path_len = Key("ignore-as-path-len")
    in_filter = Key("in-filter")
    instance = Key("instance")
    interface = Key('interface')
    interfaces = Key('interfaces')
    interface_name = Key('interface-name')
    keepalive_time = Key("keepalive-time")
    local_address = Key("local-address")
    mac_address = Key('max-address')
    multihop = Key("multihop")
    name = Key("name")
    nexthop = Key("nexthop")
    nexthop_choice = Key("nexthop-choice")
    origin = Key("origin")
    out_filter = Key("out-filter")
    passive = Key("passive")
    peer = Key("peer")
    prefix = Key("prefix")
    prefix_count = Key("prefix-count")
    rcv_from = Key('received-from')
    redistribute_connected = Key("redistribute-connected")
    redistribute_ospf = Key("redistribute-ospf")
    redistribute_other_bgp = Key("redistribute-other-bgp")
    redistribute_rip = Key("redistribute-rip")
    redistribute_static = Key("redistribute-static")
    refresh_capability = Key("refresh-capability")
    remote_address = Key("remote-address")
    remote_as = Key("remote-as")
    remote_hold_time = Key("remote-hold-time")
    remote_id = Key("remote-id")
    remove_private_as = Key("remove-private-as")
    route_reflect = Key("route-reflect")
    route_distinguisher = Key("route-distinguisher")
    router_id = Key("router-id")
    routing_mark = Key('routing-mark')
    routing_table = Key("routing-table")
    state = Key("state")
    system_caps = Key('system-caps')
    system_caps_enabled = Key('system-caps-enabled')
    system_description = Key('system-description')
    tcp_md5_key = Key("tcp-md5-key")
    ttl = Key("ttl")
    updates_received = Key("updates-received")
    updates_sent = Key("updates-sent")
    uptime = Key("uptime")
    use_bfd = Key("use-bfd")
    used_hold_time = Key("used-hold-time")
    used_keepalive_time = Key("used-keepalive-time")
    withdrawn_received = Key("withdrawn-received")


lldp_neighbors = (
    Keys.identity,
    Keys.interface_name,
    Keys.interface,
    Keys.mac_address,
    Keys.system_description,
    Keys.system_caps,
    Keys.system_caps_enabled,
)

bgp_peers = (
    Keys.address_families,
    Keys.as_override,
    Keys.as4_capability,
    Keys.default_originate,
    Keys.disabled,
    Keys.established,
    Keys.hold_time,
    Keys.in_filter,
    Keys.instance,
    Keys.keepalive_time,
    Keys.local_address,
    Keys.multihop,
    Keys.name,
    Keys.nexthop_choice,
    Keys.out_filter,
    Keys.passive,
    Keys.prefix_count,
    Keys.refresh_capability,
    Keys.remote_address,
    Keys.remote_as,
    Keys.remote_hold_time,
    Keys.remote_id,
    Keys.remove_private_as,
    Keys.route_reflect,
    Keys.state,
    Keys.tcp_md5_key,
    Keys.ttl,
    Keys.updates_received,
    Keys.updates_sent,
    Keys.uptime,
    Keys.use_bfd,
    Keys.used_hold_time,
    Keys.used_keepalive_time,
    Keys.withdrawn_received,
)

bgp_advertisments = (
    Keys.nexthop,
    Keys.origin,
    Keys.peer,
    Keys.prefix,
)

bgp_instances = (
    Keys.name,
    Keys.as_num,
    Keys.router_id,
    Keys.redistribute_connected,
    Keys.redistribute_static,
    Keys.redistribute_rip,
    Keys.redistribute_ospf,
    Keys.redistribute_other_bgp,
    Keys.out_filter,
    Keys.client_to_client_reflection,
    Keys.ignore_as_path_len,
    Keys.routing_table,
    Keys.default,
)
