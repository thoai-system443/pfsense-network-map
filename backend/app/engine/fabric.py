"""Reason about several firewalls at once.

A packet crossing two firewalls has to be permitted by both, so the verdict for
the pair is the first hop that refuses. The chain itself comes from routing: a
route's next hop names an address, and if one of the loaded firewalls owns that
address, it is the next link.

Where the next hop belongs to a device that was never loaded, the chain stops
and says so. Reporting "allowed" for the whole path would be a claim this tool
has no evidence for.
"""

import ipaddress
from dataclasses import dataclass, field

from app.engine import routing
from app.engine.evaluate import RuleRef, check, explore_from
from app.engine.ipset import IpSet
from app.engine.portset import PortSet
from app.parser.types import ParsedConfig

FAMILY = 4
MAX_HOPS = 16


@dataclass(frozen=True)
class Firewall:
    id: str
    name: str
    config: ParsedConfig


@dataclass(frozen=True)
class Hop:
    firewall_id: str
    firewall_name: str
    in_interface: str
    verdict: str
    decided_by: RuleRef | None
    out_interface: str | None = None
    next_hop: str | None = None
    translated_address: str | None = None
    translated_port: int | None = None


@dataclass
class PathResult:
    verdict: str
    hops: list[Hop] = field(default_factory=list)
    truncated: bool = False
    stopped_reason: str | None = None


@dataclass(frozen=True)
class Zone:
    cidr: str
    label: str
    firewall_ids: list[str]
    is_vlan: bool = False


def _interface_network(iface) -> ipaddress.IPv4Network | None:
    if not iface.enabled or not iface.ipaddr or iface.subnet is None:
        return None
    try:
        network = ipaddress.ip_network(f"{iface.ipaddr}/{iface.subnet}", strict=False)
    except ValueError:
        return None
    return network if network.version == FAMILY else None


def zones(firewalls: list[Firewall]) -> list[Zone]:
    """One zone per distinct subnet, however many firewalls sit on it.

    Two firewalls on the same VLAN are on one network, not two. Keying by CIDR
    makes the map describe the network rather than the pile of config files.
    """
    by_cidr: dict[str, tuple[list[str], list[str], bool]] = {}
    for firewall in firewalls:
        for iface in firewall.config.interfaces:
            network = _interface_network(iface)
            if network is None:
                continue
            cidr = str(network)
            names, owners, is_vlan = by_cidr.get(cidr, ([], [], False))
            if iface.descr not in names:
                names.append(iface.descr)
            if firewall.id not in owners:
                owners.append(firewall.id)
            by_cidr[cidr] = (names, owners, is_vlan or iface.is_vlan)

    return [
        Zone(cidr=cidr, label=" / ".join(names), firewall_ids=owners, is_vlan=is_vlan)
        for cidr, (names, owners, is_vlan) in sorted(by_cidr.items())
    ]


def _owner_of(
    firewalls: list[Firewall], address: str, exclude: str | None = None
) -> tuple[Firewall, str] | None:
    """The firewall that answers to this address, and the interface it is on.

    Exact address match is tried across every firewall before falling back to
    subnet containment. Doing both per firewall in turn lets the firewall the
    packet is leaving claim its own transit subnet and cuts the chain short,
    because the next hop always sits inside the segment they share.
    """
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None

    candidates = [firewall for firewall in firewalls if firewall.id != exclude]

    for firewall in candidates:
        for iface in firewall.config.interfaces:
            if iface.ipaddr == address:
                return firewall, iface.name

    for firewall in candidates:
        for iface in firewall.config.interfaces:
            network = _interface_network(iface)
            if network is not None and parsed in network:
                return firewall, iface.name
    return None


def _entry_point(firewalls: list[Firewall], source: str) -> tuple[Firewall, str] | None:
    """Where the packet first meets a firewall we know about."""
    try:
        parsed = ipaddress.ip_address(source)
    except ValueError:
        return None

    best: tuple[int, Firewall, str] | None = None
    for firewall in firewalls:
        for iface in firewall.config.interfaces:
            network = _interface_network(iface)
            if network is None or parsed not in network:
                continue
            if best is None or network.prefixlen > best[0]:
                best = (network.prefixlen, firewall, iface.name)
    if best is not None:
        return best[1], best[2]

    # Nothing owns the source, so it comes from outside: enter at whichever
    # firewall holds the default route.
    for firewall in firewalls:
        default = next((g for g in firewall.config.gateways if g.default and not g.disabled), None)
        if default is not None and default.interface:
            return firewall, default.interface
    return None


def path_check(
    firewalls: list[Firewall],
    source: str,
    destination: str,
    port: int | None,
    protocol: str = "any",
) -> PathResult:
    entry = _entry_point(firewalls, source)
    if entry is None:
        return PathResult(
            verdict="unrouted",
            stopped_reason=f"no loaded firewall has an interface {source} could arrive on",
        )

    firewall, in_interface = entry
    result = PathResult(verdict="pass")
    seen: set[tuple[str, str]] = set()

    for _ in range(MAX_HOPS):
        if (firewall.id, in_interface) in seen:
            result.truncated = True
            result.stopped_reason = f"routing loop back into {firewall.name} on {in_interface}"
            return result
        seen.add((firewall.id, in_interface))

        decision = check(
            firewall.config, source, destination, port, protocol, in_interface=in_interface
        )
        route = routing.lookup(routing.build_table(firewall.config), destination)

        result.hops.append(
            Hop(
                firewall_id=firewall.id,
                firewall_name=firewall.name,
                in_interface=in_interface,
                verdict=decision.verdict,
                decided_by=decision.decided_by,
                out_interface=route.out_interface if route else None,
                next_hop=route.next_hop if route else None,
                translated_address=decision.translated_address,
                translated_port=decision.translated_port,
            )
        )

        if decision.verdict != "pass":
            result.verdict = decision.verdict
            return result

        if route is None:
            result.verdict = "unrouted"
            result.stopped_reason = f"{firewall.name} has no route to {destination}"
            return result

        if route.next_hop is None:
            # Directly connected: the destination sits on this firewall's own
            # segment, so there is nothing further to cross.
            return result

        owner = _owner_of(firewalls, route.next_hop, exclude=firewall.id)
        if owner is None:
            result.truncated = True
            result.stopped_reason = (
                f"next hop {route.next_hop} belongs to a device that is not loaded here, "
                f"so anything beyond {firewall.name} was not checked"
            )
            return result

        firewall, in_interface = owner

    result.truncated = True
    result.stopped_reason = f"gave up after {MAX_HOPS} hops"
    return result


def reachable_ports(
    firewalls: list[Firewall],
    source: str,
    destination_set: IpSet,
    destination_probe: str,
    protocol: str = "any",
) -> tuple[PortSet, bool]:
    """Ports open from source into a destination set, across the whole chain.

    Each firewall on the path contributes the ports it allows into that set;
    the answer is their intersection, because every hop has to agree. Returns
    the ports and whether the chain was cut short.
    """
    entry = _entry_point(firewalls, source)
    if entry is None:
        return PortSet.empty(), False

    firewall, in_interface = entry
    allowed = PortSet.full()
    seen: set[tuple[str, str]] = set()

    for _ in range(MAX_HOPS):
        if (firewall.id, in_interface) in seen:
            return allowed, True
        seen.add((firewall.id, in_interface))

        hop_ports = PortSet.empty()
        for region in explore_from(firewall.config, source, protocol, in_interface=in_interface):
            if region.verdict != "pass":
                continue
            covered = IpSet.empty(FAMILY)
            for cidr in region.addresses:
                covered = covered.union(IpSet.from_cidr(cidr))
            if covered.intersect(destination_set).is_empty():
                continue
            hop_ports = hop_ports.union(PortSet.parse(region.ports))

        allowed = allowed.intersect(hop_ports)
        if allowed.is_empty():
            return allowed, False

        route = routing.lookup(routing.build_table(firewall.config), destination_probe)
        if route is None or route.next_hop is None:
            return allowed, False

        owner = _owner_of(firewalls, route.next_hop, exclude=firewall.id)
        if owner is None:
            return allowed, True
        firewall, in_interface = owner

    return allowed, True


def topology(firewalls: list[Firewall]) -> dict:
    """Firewalls and the networks they sit on.

    A subnet two firewalls both touch is one node with an edge to each of them.
    That is what makes the transit segment between them visible as a single
    link rather than two unrelated stubs.
    """
    nodes: list[dict] = [
        {
            "id": firewall.id,
            "label": firewall.name,
            "kind": "firewall",
            "subnet": None,
            "shared": False,
            "firewalls": [firewall.name],
        }
        for firewall in firewalls
    ]
    edges: list[dict] = []
    names = {firewall.id: firewall.name for firewall in firewalls}

    for zone in zones(firewalls):
        node_id = f"net:{zone.cidr}"
        nodes.append(
            {
                "id": node_id,
                "label": zone.label,
                "kind": "vlan" if zone.is_vlan else "interface",
                "subnet": zone.cidr,
                "shared": len(zone.firewall_ids) > 1,
                "firewalls": [names[fid] for fid in zone.firewall_ids],
            }
        )
        for firewall_id in zone.firewall_ids:
            edges.append({"source": firewall_id, "target": node_id, "kind": "link"})

    for firewall in firewalls:
        for index, tunnel in enumerate(firewall.config.vpn.tunnels):
            node_id = f"{firewall.id}:tunnel-{index}"
            fallback = tunnel.remote_networks[0] if tunnel.remote_networks else None
            nodes.append(
                {
                    "id": node_id,
                    "label": tunnel.descr or tunnel.kind,
                    "kind": "tunnel",
                    "subnet": tunnel.tunnel_network or fallback,
                    "shared": False,
                    "firewalls": [firewall.name],
                }
            )
            edges.append({"source": firewall.id, "target": node_id, "kind": "tunnel"})

    return {"nodes": nodes, "edges": edges}


INTERNET_ID = "net:internet"


def _zone_addresses(zone: Zone) -> IpSet:
    return IpSet.from_cidr(zone.cidr)


def _first_host(addresses: IpSet) -> str | None:
    if not addresses.items:
        return None
    lo, hi = addresses.items[0]
    return str(ipaddress.ip_address(lo + 1 if lo < hi else lo))


def access_graph(firewalls: list[Firewall], protocol: str = "any") -> dict:
    """Which zones reach which, with every firewall on the path taken into account.

    The port set for a pair is the intersection of what each hop allows, so a
    flow only appears when the whole chain agrees. An edge marked truncated
    means the path left the set of loaded firewalls before it could be settled.
    """
    found = zones(firewalls)
    names = {firewall.id: firewall.name for firewall in firewalls}

    internal = IpSet.empty(FAMILY)
    for zone in found:
        internal = internal.union(_zone_addresses(zone))

    entries: list[tuple[str, str, IpSet, str | None]] = [
        (f"net:{zone.cidr}", zone.label, _zone_addresses(zone), _first_host(_zone_addresses(zone)))
        for zone in found
    ]
    outside = internal.complement()
    entries.append((INTERNET_ID, "Internet", outside, "8.8.8.8"))

    nodes = [
        {
            "id": zone_id,
            "label": label,
            "kind": "internet" if zone_id == INTERNET_ID else "interface",
            "subnet": (addresses.to_cidrs() or [None])[0],
            "firewalls": [
                names[fid]
                for zone in found
                if f"net:{zone.cidr}" == zone_id
                for fid in zone.firewall_ids
            ],
        }
        for zone_id, label, addresses, _ in entries
    ]

    edges: list[dict] = []
    for source_id, _, _, probe in entries:
        if probe is None:
            continue
        for target_id, _, target_set, target_probe in entries:
            if target_id == source_id or target_probe is None:
                continue
            ports, truncated = reachable_ports(firewalls, probe, target_set, target_probe, protocol)
            if ports.is_empty():
                continue
            edges.append(
                {
                    "source": source_id,
                    "target": target_id,
                    "ports": ports.to_spec(),
                    "truncated": truncated,
                    "rules": [],
                }
            )

    return {"nodes": nodes, "edges": edges}
