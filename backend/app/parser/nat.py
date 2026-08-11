"""Parse <nat>: port forwards, 1:1 mappings, outbound rules.

Port forwards live directly under <nat> as <rule>. Their <destination> is the
address seen from outside; <target> plus <local-port> is where the traffic
actually ends up, and that translated address is what filter rules match.
"""

from app.parser.rules import parse_addr_spec
from app.parser.types import NatConfig, OneToOne, OutboundRule, PortForward
from app.parser.xmlutil import WarningCollector, has_flag, text_of

KNOWN_NAT_CHILDREN = {"rule", "onetoone", "outbound", "separator", "natreflection"}
KNOWN_PF_CHILDREN = {
    "interface",
    "protocol",
    "target",
    "local-port",
    "source",
    "destination",
    "descr",
    "disabled",
    "associated-rule-id",
    "created",
    "updated",
    "nordr",
    "natreflection",
    "nosync",
    "ipprotocol",
    "tag",
    "tagged",
}
KNOWN_1TO1_CHILDREN = {
    "interface",
    "external",
    "source",
    "destination",
    "descr",
    "disabled",
    "natreflection",
    "nobinat",
    "ipprotocol",
    "created",
    "updated",
}
KNOWN_OUTBOUND_CHILDREN = {"mode", "rule"}
KNOWN_OUTBOUND_RULE_CHILDREN = {
    "interface",
    "source",
    "sourceport",
    "destination",
    "dstport",
    "target",
    "targetip",
    "targetip_subnet",
    "descr",
    "disabled",
    "staticnatport",
    "nonat",
    "poolopts",
    "created",
    "updated",
    "protocol",
    "ipprotocol",
    "source_hash_key",
}


def parse_nat(root, warnings: WarningCollector) -> NatConfig:
    section = root.find("nat")
    if section is None:
        return NatConfig()

    warnings.check_children(section, "pfsense/nat", KNOWN_NAT_CHILDREN)
    config = NatConfig()

    for index, node in enumerate(section.findall("rule")):
        path = f"pfsense/nat/rule[{index}]"
        warnings.check_children(node, path, KNOWN_PF_CHILDREN)
        config.port_forwards.append(
            PortForward(
                interface=text_of(node, "interface", "") or "",
                protocol=(text_of(node, "protocol", "any") or "any").lower(),
                destination=parse_addr_spec(
                    node.find("destination"), f"{path}/destination", warnings
                ),
                target=text_of(node, "target", "") or "",
                local_port=text_of(node, "local-port"),
                disabled=has_flag(node, "disabled"),
                descr=text_of(node, "descr", "") or "",
            )
        )

    for index, node in enumerate(section.findall("onetoone")):
        path = f"pfsense/nat/onetoone[{index}]"
        warnings.check_children(node, path, KNOWN_1TO1_CHILDREN)
        source = parse_addr_spec(node.find("source"), f"{path}/source", warnings)
        config.one_to_one.append(
            OneToOne(
                interface=text_of(node, "interface", "") or "",
                external=text_of(node, "external", "") or "",
                internal=source.address or source.network or "",
                disabled=has_flag(node, "disabled"),
                descr=text_of(node, "descr", "") or "",
            )
        )

    outbound = section.find("outbound")
    if outbound is not None:
        warnings.check_children(outbound, "pfsense/nat/outbound", KNOWN_OUTBOUND_CHILDREN)
        for index, node in enumerate(outbound.findall("rule")):
            path = f"pfsense/nat/outbound/rule[{index}]"
            warnings.check_children(node, path, KNOWN_OUTBOUND_RULE_CHILDREN)
            source = parse_addr_spec(node.find("source"), f"{path}/source", warnings)
            destination = parse_addr_spec(node.find("destination"), f"{path}/destination", warnings)
            config.outbound.append(
                OutboundRule(
                    interface=text_of(node, "interface", "") or "",
                    source=source.network or source.address or "any",
                    destination="any" if destination.any else (destination.network or ""),
                    target=text_of(node, "target", "") or "interface address",
                    descr=text_of(node, "descr", "") or "",
                )
            )

    return config
