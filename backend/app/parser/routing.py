"""Parse <gateways> and <staticroutes>.

Left out of the original scope on purpose: with a single firewall, every rule
is evaluated on the interface the source address belongs to and routing never
enters into it. As soon as a second firewall is loaded, the routing table is
the only thing that says which firewalls a packet crosses.
"""

from app.parser.types import Gateway, StaticRoute
from app.parser.xmlutil import WarningCollector, has_flag, text_of

KNOWN_GATEWAY_CHILDREN = {
    "interface",
    "gateway",
    "name",
    "weight",
    "ipprotocol",
    "descr",
    "defaultgw",
    "monitor",
    "monitor_disable",
    "action_disable",
    "gw_down_kill_states",
    "disabled",
    "latencylow",
    "latencyhigh",
    "losslow",
    "losshigh",
    "interval",
    "alert_interval",
    "time_period",
    "data_payload",
    "nonlocalgateway",
}
KNOWN_ROUTE_CHILDREN = {"network", "gateway", "descr", "disabled"}


def parse_gateways(root, warnings: WarningCollector) -> list[Gateway]:
    section = root.find("gateways")
    if section is None:
        return []

    out: list[Gateway] = []
    for index, node in enumerate(section.findall("gateway_item")):
        path = f"pfsense/gateways/gateway_item[{index}]"
        warnings.check_children(node, path, KNOWN_GATEWAY_CHILDREN)
        name = text_of(node, "name")
        address = text_of(node, "gateway")
        if not name or not address:
            warnings.add(path, "gateway without a name or address, ignored", "error")
            continue
        out.append(
            Gateway(
                name=name,
                interface=text_of(node, "interface", "") or "",
                address=address,
                default=has_flag(node, "defaultgw"),
                disabled=has_flag(node, "disabled"),
                descr=text_of(node, "descr", "") or "",
            )
        )
    return out


def parse_static_routes(root, warnings: WarningCollector) -> list[StaticRoute]:
    section = root.find("staticroutes")
    if section is None:
        return []

    out: list[StaticRoute] = []
    for index, node in enumerate(section.findall("route")):
        path = f"pfsense/staticroutes/route[{index}]"
        warnings.check_children(node, path, KNOWN_ROUTE_CHILDREN)
        network = text_of(node, "network")
        gateway = text_of(node, "gateway")
        if not network or not gateway:
            warnings.add(path, "route without a network or gateway, ignored", "error")
            continue
        out.append(
            StaticRoute(
                network=network,
                gateway=gateway,
                disabled=has_flag(node, "disabled"),
                descr=text_of(node, "descr", "") or "",
            )
        )
    return out
