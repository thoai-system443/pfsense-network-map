"""Parse <filter><rule>.

Two defaults matter and are easy to get wrong. Interface rules are emitted by
pfSense with the quick flag, so within an interface the first match wins.
Floating rules are NOT quick unless <quick> is present, which is what lets a
later interface rule override a matching floating rule.
"""

from app.parser.types import AddrSpec, FilterRule
from app.parser.xmlutil import WarningCollector, has_flag, text_of

KNOWN_RULE_CHILDREN = {
    "id",
    "tracker",
    "type",
    "interface",
    "ipprotocol",
    "protocol",
    "source",
    "destination",
    "descr",
    "disabled",
    "floating",
    "quick",
    "direction",
    "log",
    "statetype",
    "created",
    "updated",
    "tag",
    "tagged",
    "max",
    "max-src-nodes",
    "max-src-conn",
    "max-src-states",
    "statetimeout",
    "os",
    "icmptype",
    "sched",
    "gateway",
    "dnpipe",
    "pdnpipe",
    "defaultqueue",
    "ackqueue",
    "associated-rule-id",
}
KNOWN_ADDR_CHILDREN = {"any", "network", "address", "not", "port"}
VALID_ACTIONS = {"pass", "block", "reject"}
VALID_IPPROTOCOLS = {"inet", "inet6", "inet46"}


def parse_addr_spec(element, path: str, warnings: WarningCollector) -> AddrSpec:
    if element is None:
        return AddrSpec(any=True)
    warnings.check_children(element, path, KNOWN_ADDR_CHILDREN)
    return AddrSpec(
        any=has_flag(element, "any"),
        network=text_of(element, "network"),
        address=text_of(element, "address"),
        not_=has_flag(element, "not"),
        port=text_of(element, "port"),
    )


def parse_rules(root, warnings: WarningCollector) -> list[FilterRule]:
    section = root.find("filter")
    if section is None:
        return []

    out: list[FilterRule] = []
    for seq, node in enumerate(section.findall("rule")):
        path = f"pfsense/filter/rule[{seq}]"
        warnings.check_children(node, path, KNOWN_RULE_CHILDREN)

        floating = has_flag(node, "floating")
        action = text_of(node, "type", "pass")
        if action not in VALID_ACTIONS:
            warnings.add(path, f"unknown rule type {action!r}, treated as block", "error")
            action = "block"

        ipprotocol = text_of(node, "ipprotocol", "inet")
        if ipprotocol not in VALID_IPPROTOCOLS:
            warnings.add(path, f"unknown ipprotocol {ipprotocol!r}, treated as inet")
            ipprotocol = "inet"

        raw_interface = text_of(node, "interface", "") or ""
        out.append(
            FilterRule(
                seq=seq,
                interfaces=[p.strip() for p in raw_interface.split(",") if p.strip()],
                floating=floating,
                quick=has_flag(node, "quick") if floating else True,
                direction=text_of(node, "direction", "any" if floating else "in"),
                action=action,
                disabled=has_flag(node, "disabled"),
                ipprotocol=ipprotocol,
                protocol=(text_of(node, "protocol", "any") or "any").lower(),
                source=parse_addr_spec(node.find("source"), f"{path}/source", warnings),
                destination=parse_addr_spec(
                    node.find("destination"), f"{path}/destination", warnings
                ),
                descr=text_of(node, "descr", "") or "",
                tracker=text_of(node, "tracker"),
            )
        )
    return out
