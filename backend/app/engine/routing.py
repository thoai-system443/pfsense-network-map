"""Build a firewall's routing table and answer "where does this address go".

Three sources, in the order the kernel would prefer them: directly connected
interface subnets, static routes, and the default gateway. Lookup is longest
prefix first, so a /24 static route beats the /16 it sits inside and both beat
the default route.
"""

import ipaddress
from dataclasses import dataclass

from app.parser.types import ParsedConfig

FAMILY = 4


@dataclass(frozen=True)
class RouteEntry:
    network: str
    prefix_length: int
    out_interface: str
    next_hop: str | None
    kind: str
    descr: str = ""


def _interface_networks(config: ParsedConfig) -> list[tuple[str, ipaddress.IPv4Network]]:
    out: list[tuple[str, ipaddress.IPv4Network]] = []
    for iface in config.interfaces:
        if not iface.enabled or not iface.ipaddr or iface.subnet is None:
            continue
        try:
            network = ipaddress.ip_network(f"{iface.ipaddr}/{iface.subnet}", strict=False)
        except ValueError:
            continue
        if network.version == FAMILY:
            out.append((iface.name, network))
    return out


def _interface_for_address(config: ParsedConfig, address: str) -> str | None:
    """Which interface a next-hop address sits on, longest prefix first."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    best: tuple[int, str] | None = None
    for name, network in _interface_networks(config):
        if parsed in network and (best is None or network.prefixlen > best[0]):
            best = (network.prefixlen, name)
    return best[1] if best else None


def build_table(config: ParsedConfig) -> list[RouteEntry]:
    entries: list[RouteEntry] = []

    for name, network in _interface_networks(config):
        entries.append(
            RouteEntry(
                network=str(network),
                prefix_length=network.prefixlen,
                out_interface=name,
                next_hop=None,
                kind="connected",
            )
        )

    gateways = {g.name: g for g in config.gateways if not g.disabled}

    for route in config.static_routes:
        if route.disabled:
            continue
        gateway = gateways.get(route.gateway)
        if gateway is None:
            # A route pointing at a gateway that no longer exists is dead in the
            # kernel too, so dropping it keeps the table honest.
            continue
        try:
            network = ipaddress.ip_network(route.network, strict=False)
        except ValueError:
            continue
        if network.version != FAMILY:
            continue
        out_interface = gateway.interface or _interface_for_address(config, gateway.address)
        if not out_interface:
            continue
        entries.append(
            RouteEntry(
                network=str(network),
                prefix_length=network.prefixlen,
                out_interface=out_interface,
                next_hop=gateway.address,
                kind="static",
                descr=route.descr,
            )
        )

    default = next((g for g in gateways.values() if g.default), None)
    if default is not None:
        out_interface = default.interface or _interface_for_address(config, default.address)
        if out_interface:
            entries.append(
                RouteEntry(
                    network="0.0.0.0/0",
                    prefix_length=0,
                    out_interface=out_interface,
                    next_hop=default.address,
                    kind="default",
                    descr=default.descr,
                )
            )

    return sorted(entries, key=lambda entry: entry.prefix_length, reverse=True)


def lookup(table: list[RouteEntry], address: str) -> RouteEntry | None:
    """The entry a packet to this address would follow, or None if unroutable."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    if parsed.version != FAMILY:
        return None

    for entry in table:
        try:
            network = ipaddress.ip_network(entry.network, strict=False)
        except ValueError:
            continue
        if parsed in network:
            return entry
    return None
