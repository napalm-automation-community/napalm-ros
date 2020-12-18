from librouteros.query import Key

not_disabled = Key('disabled') == False


class Keys:
    bgp = Key('bgp')
    dst_addr = Key('dst-address')
    rcv_from = Key('received-from')
    mac_address = Key('max-address')
    interface = Key('interface')
    address = Key('address')


lldp_neighbors = (
    Key('identity'),
    Key('interface-name'),
    Key('interface'),
    Key('mac-address'),
    Key('system-description'),
    Key('system-caps'),
    Key('system-caps-enabled'),
)

bgp_peers = (
    Key("address-families"),
    Key("as-override"),
    Key("as4-capability"),
    Key("default-originate"),
    Key("disabled"),
    Key("established"),
    Key("hold-time"),
    Key("in-filter"),
    Key("instance"),
    Key("keepalive-time"),
    Key("local-address"),
    Key("multihop"),
    Key("name"),
    Key("nexthop-choice"),
    Key("out-filter"),
    Key("passive"),
    Key("prefix-count"),
    Key("refresh-capability"),
    Key("remote-address"),
    Key("remote-as"),
    Key("remote-hold-time"),
    Key("remote-id"),
    Key("remove-private-as"),
    Key("route-reflect"),
    Key("state"),
    Key("tcp-md5-key"),
    Key("ttl"),
    Key("updates-received"),
    Key("updates-sent"),
    Key("uptime"),
    Key("use-bfd"),
    Key("used-hold-time"),
    Key("used-keepalive-time"),
    Key("withdrawn-received"),
)

bgp_advertisments = (
    Key("nexthop"),
    Key("origin"),
    Key("peer"),
    Key("prefix"),
)

bgp_instances = (
    Key("name"),
    Key("as"),
    Key("router-id"),
    Key("redistribute-connected"),
    Key("redistribute-static"),
    Key("redistribute-rip"),
    Key("redistribute-ospf"),
    Key("redistribute-other-bgp"),
    Key("out-filter"),
    Key("client-to-client-reflection"),
    Key("ignore-as-path-len"),
    Key("routing-table"),
    Key("default"),
)
