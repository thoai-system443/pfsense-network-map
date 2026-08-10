"""Parse <interfaces> and <vlans>.

pfSense stores each interface as an element named after its logical name
(wan, lan, opt1...). VLANs live in a separate <vlans> section and are joined
back to interfaces through the <vlanif> device name.
"""

from app.parser.types import Interface
from app.parser.xmlutil import WarningCollector, has_flag, text_of

KNOWN_INTERFACE_CHILDREN = {
    "if",
    "descr",
    "enable",
    "ipaddr",
    "subnet",
    "ipaddrv6",
    "subnetv6",
    "gateway",
    "gatewayv6",
    "spoofmac",
    "mtu",
    "mss",
    "media",
    "mediaopt",
    "blockbogons",
    "blockpriv",
    "dhcphostname",
    "alias-address",
    "alias-subnet",
    "track6-interface",
    "track6-prefix-id",
}
KNOWN_VLAN_CHILDREN = {"if", "tag", "vlanif", "descr", "pcp"}


def _vlan_index(root, warnings: WarningCollector) -> dict[str, tuple[str, int]]:
    """Map device name (em2.20) to (parent device, tag)."""
    index: dict[str, tuple[str, int]] = {}
    section = root.find("vlans")
    if section is None:
        return index
    for node in section.findall("vlan"):
        warnings.check_children(node, "pfsense/vlans/vlan", KNOWN_VLAN_CHILDREN)
        parent = text_of(node, "if")
        tag = text_of(node, "tag")
        device = text_of(node, "vlanif") or (f"{parent}.{tag}" if parent and tag else None)
        if device and parent and tag:
            index[device] = (parent, int(tag))
    return index


def parse_interfaces(root, warnings: WarningCollector) -> list[Interface]:
    section = root.find("interfaces")
    if section is None:
        return []

    vlans = _vlan_index(root, warnings)
    out: list[Interface] = []
    for node in section:
        path = f"pfsense/interfaces/{node.tag}"
        warnings.check_children(node, path, KNOWN_INTERFACE_CHILDREN)
        device = text_of(node, "if", "") or ""
        subnet = text_of(node, "subnet")
        parent, tag = vlans.get(device, (None, None))
        out.append(
            Interface(
                name=node.tag,
                descr=text_of(node, "descr") or node.tag.upper(),
                if_=device,
                ipaddr=text_of(node, "ipaddr"),
                subnet=int(subnet) if subnet and subnet.isdigit() else None,
                enabled=has_flag(node, "enable"),
                is_vlan=device in vlans,
                vlan_tag=tag,
                parent_if=parent,
            )
        )
    return out
