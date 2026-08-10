"""Assemble the ordered rule list pf would evaluate for one inbound interface.

Order is floating rules, then interface group rules, then the interface's own
rules. Disabled rules never enter the list. The implicit anti-lockout rule on
LAN is synthesised because pfSense adds it at runtime, not in config.xml.

No block-all rule is appended: default deny is handled by the evaluator when it
runs off the end of the list without a match.
"""

import ipaddress

from app.parser.types import AddrSpec, FilterRule, ParsedConfig

ANTI_LOCKOUT_PORTS = "22,80,443"


def inbound_interface(config: ParsedConfig, source_ip: str) -> str:
    """Pick the interface whose subnet contains source_ip, longest prefix first."""
    try:
        address = ipaddress.ip_address(source_ip)
    except ValueError:
        return "wan"

    best_name = "wan"
    best_prefix = -1
    for iface in config.interfaces:
        if not iface.ipaddr or iface.subnet is None:
            continue
        try:
            network = ipaddress.ip_network(f"{iface.ipaddr}/{iface.subnet}", strict=False)
        except ValueError:
            continue
        if network.version != address.version or address not in network:
            continue
        if network.prefixlen > best_prefix:
            best_name, best_prefix = iface.name, network.prefixlen
    return best_name


def _anti_lockout(config: ParsedConfig) -> FilterRule | None:
    lan = config.interface_by_name("lan")
    if lan is None or not lan.ipaddr:
        return None
    return FilterRule(
        seq=-1,
        interfaces=["lan"],
        floating=False,
        quick=True,
        direction="in",
        action="pass",
        ipprotocol="inet",
        protocol="tcp",
        source=AddrSpec(any=True),
        destination=AddrSpec(network="lanip", port=ANTI_LOCKOUT_PORTS),
        descr="Implicit anti-lockout rule",
        synthetic=True,
    )


def build(config: ParsedConfig, in_iface: str) -> list[FilterRule]:
    active = [r for r in config.rules if not r.disabled]

    floating = [
        r
        for r in active
        if r.floating
        and r.direction in {"in", "any"}
        and (not r.interfaces or in_iface in r.interfaces)
    ]
    on_interface = [r for r in active if not r.floating and in_iface in r.interfaces]

    out = floating + on_interface
    if in_iface == "lan":
        lockout = _anti_lockout(config)
        if lockout is not None:
            out.append(lockout)
    return out
