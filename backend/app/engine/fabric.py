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
from app.engine.evaluate import RuleRef, check, check_regions, explore_from
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
    if ":" in source or ":" in destination:
        # Every address set in this module is built with FAMILY = 4. Saying so
        # beats returning "no firewall could receive this", which blames the
        # configuration for a gap in the tool.
        return PathResult(
            verdict="unrouted",
            truncated=True,
            stopped_reason=(
                "IPv6 is not supported for multi-firewall analysis yet; "
                "use the single-firewall Path check tab"
            ),
        )

    entry = _entry_point(firewalls, source)
    if entry is None:
        return PathResult(
            verdict="unrouted",
            stopped_reason=f"no loaded firewall has an interface {source} could arrive on",
        )

    firewall, in_interface = entry
    result = PathResult(verdict="pass")
    seen: set[tuple[str, str]] = set()

    # Both are rewritten as the packet crosses a firewall that translates them.
    # Routing the original public address instead is what made a published
    # service look reachable when the firewall behind it refused the traffic.
    current_destination = destination
    current_port = port

    for _ in range(MAX_HOPS):
        if (firewall.id, in_interface) in seen:
            result.truncated = True
            result.stopped_reason = f"routing loop back into {firewall.name} on {in_interface}"
            return result
        seen.add((firewall.id, in_interface))

        decision = check(
            firewall.config,
            source,
            current_destination,
            current_port,
            protocol,
            in_interface=in_interface,
        )
        if decision.translated_address:
            current_destination = decision.translated_address
            current_port = decision.translated_port
        route = routing.lookup(routing.build_table(firewall.config), current_destination)

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
            result.stopped_reason = f"{firewall.name} has no route to {current_destination}"
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


class _Memo:
    """Per-request cache for the two expensive calls.

    Without it access_graph rebuilds a routing table and re-runs explore_from
    for every ordered pair of zones, which is O(zones squared) evaluations of
    the same handful of rulesets.
    """

    def __init__(self) -> None:
        self.tables: dict[str, list] = {}
        self.explored: dict[tuple[str, str, str, str], list] = {}

    def table(self, firewall: Firewall):
        if firewall.id not in self.tables:
            self.tables[firewall.id] = routing.build_table(firewall.config)
        return self.tables[firewall.id]

    def explore(self, firewall: Firewall, source: str, protocol: str, in_interface: str):
        key = (firewall.id, source, protocol, in_interface)
        if key not in self.explored:
            self.explored[key] = explore_from(
                firewall.config, source, protocol, in_interface=in_interface
            )
        return self.explored[key]


def reachable_ports(
    firewalls: list[Firewall],
    source: str,
    destination_set: IpSet,
    destination_probe: str,
    protocol: str = "any",
    memo: "_Memo | None" = None,
) -> tuple[PortSet, bool]:
    """Ports open from source into a destination set, across the whole chain.

    Each firewall on the path contributes the ports it allows into that set;
    the answer is their intersection, because every hop has to agree. Returns
    the ports and whether the chain was cut short.
    """
    memo = memo or _Memo()
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
        for region in memo.explore(firewall, source, protocol, in_interface):
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

        route = routing.lookup(memo.table(firewall), destination_probe)
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

    # One cache for the whole graph: every pair re-asks the same firewalls the
    # same questions.
    memo = _Memo()
    edges: list[dict] = []
    for source_id, _, _, probe in entries:
        if probe is None:
            continue
        for target_id, _, target_set, target_probe in entries:
            if target_id == source_id or target_probe is None:
                continue
            ports, truncated = reachable_ports(
                firewalls, probe, target_set, target_probe, protocol, memo=memo
            )
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


@dataclass
class PathRegionResult:
    """One part of the source x destination space, and how far it got."""

    sources: list[str]
    destinations: list[str]
    verdict: str
    hops: list[Hop] = field(default_factory=list)
    truncated: bool = False
    stopped_reason: str | None = None


MAX_REGIONS = 256


def _union_cidrs(cidrs: list[str], family: int) -> IpSet:
    out = IpSet.empty(family)
    for cidr in cidrs:
        out = out.union(IpSet.from_cidr(cidr))
    return out


def _split_by_entry_point(
    firewalls: list[Firewall], sources: IpSet
) -> list[tuple[Firewall | None, str, IpSet]]:
    """Carve the source set by which firewall and interface it arrives on.

    _entry_point answers for one address by longest prefix. Sorting every
    interface subnet by prefix length and carving in that order gives the same
    answer for every address in the set at once.
    """
    subnets: list[tuple[int, Firewall, str, ipaddress.IPv4Network]] = []
    for firewall in firewalls:
        for iface in firewall.config.interfaces:
            network = _interface_network(iface)
            if network is not None:
                subnets.append((network.prefixlen, firewall, iface.name, network))
    subnets.sort(key=lambda item: item[0], reverse=True)

    remaining = sources
    out: list[tuple[Firewall | None, str, IpSet]] = []
    for _, firewall, iface_name, network in subnets:
        if remaining.is_empty():
            break
        claimed = remaining.intersect(IpSet.from_cidr(str(network)))
        if claimed.is_empty():
            continue
        out.append((firewall, iface_name, claimed))
        remaining = remaining.subtract(claimed)

    if not remaining.is_empty():
        # Nothing owns these, so they come from outside: enter wherever the
        # default route lives, matching _entry_point.
        for firewall in firewalls:
            default = next(
                (g for g in firewall.config.gateways if g.default and not g.disabled), None
            )
            if default is not None and default.interface:
                out.append((firewall, default.interface, remaining))
                break
        else:
            out.append((None, "", remaining))
    return out


def path_check_regions(
    firewalls: list[Firewall],
    source_set: IpSet,
    destination_set: IpSet,
    port: int | None,
    protocol: str = "any",
) -> list[PathRegionResult]:
    """path_check for sets: every part of the space gets its own chain.

    Two hosts in one subnet can enter at different firewalls, be translated
    differently and be refused at different hops. Collapsing the input to one
    address hides all three, so the space is carried through the chain as a set
    and split whenever the ruleset or the routing table treats parts of it
    differently.
    """
    family = source_set.family
    results: list[PathRegionResult] = []

    queue: list[tuple[Firewall, str, IpSet, IpSet, int | None, list[Hop], frozenset]] = []
    for firewall, in_interface, sources in _split_by_entry_point(firewalls, source_set):
        if firewall is None:
            results.append(
                PathRegionResult(
                    sources=sources.to_cidrs(),
                    destinations=destination_set.to_cidrs(),
                    verdict="unrouted",
                    stopped_reason=(
                        "no loaded firewall has an interface this source could arrive on"
                    ),
                )
            )
            continue
        queue.append((firewall, in_interface, sources, destination_set, port, [], frozenset()))

    while queue:
        if len(results) >= MAX_REGIONS:
            results.append(
                PathRegionResult(
                    sources=[],
                    destinations=[],
                    verdict="unrouted",
                    truncated=True,
                    stopped_reason=(
                        f"stopped after {MAX_REGIONS} distinct regions; "
                        "narrow the query to see the rest"
                    ),
                )
            )
            break

        firewall, in_interface, sources, destinations, hop_port, hops, seen = queue.pop(0)

        if (firewall.id, in_interface) in seen:
            results.append(
                PathRegionResult(
                    sources=sources.to_cidrs(),
                    destinations=destinations.to_cidrs(),
                    verdict="pass",
                    hops=hops,
                    truncated=True,
                    stopped_reason=f"routing loop back into {firewall.name} on {in_interface}",
                )
            )
            continue
        if len(hops) >= MAX_HOPS:
            results.append(
                PathRegionResult(
                    sources=sources.to_cidrs(),
                    destinations=destinations.to_cidrs(),
                    verdict="pass",
                    hops=hops,
                    truncated=True,
                    stopped_reason=f"gave up after {MAX_HOPS} hops",
                )
            )
            continue
        seen = seen | {(firewall.id, in_interface)}

        decision = check_regions(
            firewall.config, sources, destinations, hop_port, protocol, in_interface=in_interface
        )
        table = routing.build_table(firewall.config)

        for region in decision.regions:
            region_sources = _union_cidrs(region.sources, family)
            forwarded = (
                IpSet.from_cidr(region.translated_address)
                if region.translated_address
                else _union_cidrs(region.destinations, family)
            )
            next_port = region.translated_port if region.translated_address else hop_port

            if region.verdict != "pass":
                results.append(
                    PathRegionResult(
                        sources=region.sources,
                        destinations=region.destinations,
                        verdict=region.verdict,
                        hops=[
                            *hops,
                            Hop(
                                firewall_id=firewall.id,
                                firewall_name=firewall.name,
                                in_interface=in_interface,
                                verdict=region.verdict,
                                decided_by=region.decided_by,
                                translated_address=region.translated_address,
                                translated_port=region.translated_port,
                            ),
                        ],
                    )
                )
                continue

            for route, chunk in routing.split_by_route(table, forwarded):
                hop = Hop(
                    firewall_id=firewall.id,
                    firewall_name=firewall.name,
                    in_interface=in_interface,
                    verdict="pass",
                    decided_by=region.decided_by,
                    out_interface=route.out_interface if route else None,
                    next_hop=route.next_hop if route else None,
                    translated_address=region.translated_address,
                    translated_port=region.translated_port,
                )
                # What the caller asked about, not the post-NAT address: the
                # translated target is already reported on the hop.
                shown = region.destinations if region.translated_address else chunk.to_cidrs()

                if route is None:
                    results.append(
                        PathRegionResult(
                            sources=region.sources,
                            destinations=shown,
                            verdict="unrouted",
                            hops=[*hops, hop],
                            stopped_reason=f"{firewall.name} has no route to these addresses",
                        )
                    )
                    continue

                if route.next_hop is None:
                    results.append(
                        PathRegionResult(
                            sources=region.sources,
                            destinations=shown,
                            verdict="pass",
                            hops=[*hops, hop],
                        )
                    )
                    continue

                owner = _owner_of(firewalls, route.next_hop, exclude=firewall.id)
                if owner is None:
                    results.append(
                        PathRegionResult(
                            sources=region.sources,
                            destinations=shown,
                            verdict="pass",
                            hops=[*hops, hop],
                            truncated=True,
                            stopped_reason=(
                                f"next hop {route.next_hop} belongs to a device that is not "
                                f"loaded here, so anything beyond {firewall.name} was not checked"
                            ),
                        )
                    )
                    continue

                next_firewall, next_interface = owner
                queue.append(
                    (
                        next_firewall,
                        next_interface,
                        region_sources,
                        chunk,
                        next_port,
                        [*hops, hop],
                        seen,
                    )
                )

    return results
