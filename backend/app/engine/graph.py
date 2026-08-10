"""Build the two graphs the UI renders.

Topology answers "what does this network look like": one node per enabled
interface, VLAN, and tunnel, all hanging off the firewall.

The access graph answers "who can reach whom": for each ordered pair of zones
it runs explore_from from a representative address inside the origin and keeps
the slice that lands inside the target.
"""

import ipaddress
from dataclasses import asdict

from app.engine.evaluate import explore_from
from app.engine.ipset import IpSet
from app.engine.portset import PortSet
from app.engine.resolver import Resolver
from app.parser.types import ParsedConfig

FIREWALL_ID = "__firewall__"
INTERNET_ID = "internet"


def topology(config: ParsedConfig) -> dict:
    resolver = Resolver(config)
    nodes: list[dict] = [
        {
            "id": FIREWALL_ID,
            "label": config.hostname or "pfSense",
            "kind": "firewall",
            "subnet": None,
        }
    ]
    edges: list[dict] = []

    for iface in config.interfaces:
        if not iface.enabled:
            continue
        cidrs = resolver.interface_subnet(iface.name, 4).to_cidrs()
        nodes.append(
            {
                "id": iface.name,
                "label": iface.descr,
                "kind": "vlan" if iface.is_vlan else "interface",
                "subnet": cidrs[0] if cidrs else None,
            }
        )
        edges.append({"source": FIREWALL_ID, "target": iface.name, "kind": "link"})

    for index, tunnel in enumerate(config.vpn.tunnels):
        node_id = f"tunnel-{index}"
        fallback = tunnel.remote_networks[0] if tunnel.remote_networks else None
        nodes.append(
            {
                "id": node_id,
                "label": tunnel.descr or tunnel.kind,
                "kind": "tunnel",
                "subnet": tunnel.tunnel_network or fallback,
            }
        )
        edges.append({"source": FIREWALL_ID, "target": node_id, "kind": "tunnel"})

    return {"nodes": nodes, "edges": edges}


def _first_host(addresses: IpSet) -> str | None:
    """Pick a representative address inside a zone to probe with."""
    if not addresses.items:
        return None
    lo, hi = addresses.items[0]
    return str(ipaddress.ip_address(lo + 1 if lo < hi else lo))


def _zones(config: ParsedConfig, resolver: Resolver) -> list[dict]:
    zones: list[dict] = []
    internal = IpSet.empty(4)
    for iface in config.interfaces:
        if not iface.enabled:
            continue
        subnet = resolver.interface_subnet(iface.name, 4)
        if subnet.is_empty():
            continue
        zones.append({"id": iface.name, "label": iface.descr, "kind": "interface", "set": subnet})
        internal = internal.union(subnet)
    for index, tunnel in enumerate(config.vpn.tunnels):
        reachable = IpSet.empty(4)
        for cidr in [tunnel.tunnel_network, *tunnel.remote_networks]:
            if not cidr:
                continue
            try:
                part = IpSet.from_cidr(cidr)
            except ValueError:
                continue
            if part.family == 4:
                reachable = reachable.union(part)
        if reachable.is_empty():
            continue
        zones.append(
            {
                "id": f"tunnel-{index}",
                "label": tunnel.descr or tunnel.kind,
                "kind": "tunnel",
                "set": reachable,
            }
        )
        internal = internal.union(reachable)

    zones.append(
        {"id": INTERNET_ID, "label": "Internet", "kind": "internet", "set": internal.complement()}
    )
    return zones


def access_graph(config: ParsedConfig, protocol: str = "any") -> dict:
    resolver = Resolver(config)
    zones = _zones(config, resolver)
    nodes = [
        {
            "id": zone["id"],
            "label": zone["label"],
            "kind": zone["kind"],
            "subnet": (zone["set"].to_cidrs() or [None])[0],
        }
        for zone in zones
    ]

    edges: list[dict] = []
    for origin in zones:
        probe = "8.8.8.8" if origin["id"] == INTERNET_ID else _first_host(origin["set"])
        if probe is None:
            continue

        allowed = [r for r in explore_from(config, probe, protocol) if r.verdict == "pass"]
        for target in zones:
            if target["id"] == origin["id"]:
                continue
            ports = PortSet.empty()
            rules: list[dict] = []
            for region in allowed:
                covered = IpSet.empty(4)
                for cidr in region.addresses:
                    covered = covered.union(IpSet.from_cidr(cidr))
                if covered.intersect(target["set"]).is_empty():
                    continue
                ports = ports.union(PortSet.parse(region.ports))
                if region.decided_by is not None:
                    entry = asdict(region.decided_by)
                    if entry not in rules:
                        rules.append(entry)
            if ports.is_empty():
                continue
            edges.append(
                {
                    "source": origin["id"],
                    "target": target["id"],
                    "ports": ports.to_spec(),
                    "rules": rules,
                }
            )

    return {"nodes": nodes, "edges": edges}
