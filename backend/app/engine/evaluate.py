"""Evaluate traffic against a parsed pfSense configuration.

pf keeps the last matching rule and lets a later rule replace it, unless a
rule carries the quick flag, which stops evaluation immediately. pfSense emits
interface rules with quick and floating rules without it, so the loop below
reproduces the override behaviour rather than assuming first-match-wins.
"""

from dataclasses import dataclass, field

from app.engine import nat, ruleset
from app.engine.ipset import IpSet
from app.engine.match import family_matches, protocol_matches
from app.engine.portset import PortSet
from app.engine.rect import RectSet
from app.engine.resolver import Resolver
from app.parser.types import FilterRule, ParsedConfig


@dataclass(frozen=True)
class RuleRef:
    seq: int
    interface: str
    action: str
    descr: str
    tracker: str | None
    floating: bool
    quick: bool
    synthetic: bool

    @classmethod
    def of(cls, rule: FilterRule) -> "RuleRef":
        return cls(
            seq=rule.seq,
            interface=",".join(rule.interfaces),
            action=rule.action,
            descr=rule.descr,
            tracker=rule.tracker,
            floating=rule.floating,
            quick=rule.quick,
            synthetic=rule.synthetic,
        )


@dataclass(frozen=True)
class TraceEntry:
    rule: RuleRef
    matched: bool
    reason: str


@dataclass
class CheckResult:
    verdict: str
    decided_by: RuleRef | None
    in_interface: str
    translated_address: str | None = None
    translated_port: int | None = None
    unresolved: bool = False
    trace: list[TraceEntry] = field(default_factory=list)


def decides(rule: FilterRule) -> bool:
    """Whether a matching rule settles the verdict.

    A `match` rule assigns a queue or limiter and evaluation carries on. Letting
    it decide would turn a floating shaper rule covering any->any into a block
    on everything, and the tool would report traffic as denied while the
    firewall was letting it through.
    """
    return rule.action != "match"


def rule_matches(
    resolver: Resolver,
    rule: FilterRule,
    family: int,
    source: str,
    destination: str,
    port: int | None,
    protocol: str,
) -> tuple[bool, str, bool]:
    """Return (matched, reason, unresolved)."""
    if not family_matches(rule.ipprotocol, family):
        return False, f"address family {rule.ipprotocol} does not apply", False
    if not protocol_matches(rule.protocol, protocol):
        return False, f"protocol {rule.protocol} does not apply", False

    source_set, source_unresolved = resolver.addresses(rule.source, family)
    if not source_set.contains_ip(source):
        return False, "source does not match", source_unresolved

    dest_set, dest_unresolved = resolver.addresses(rule.destination, family)
    unresolved = source_unresolved or dest_unresolved
    if not dest_set.contains_ip(destination):
        return False, "destination does not match", unresolved

    if port is not None:
        port_set, port_unresolved = resolver.ports(rule.destination)
        unresolved = unresolved or port_unresolved
        if not port_set.intersect(PortSet.parse(str(port))).items:
            return False, "destination port does not match", unresolved

    return True, "matched", unresolved


def check(
    config: ParsedConfig,
    source: str,
    destination: str,
    port: int | None,
    protocol: str = "any",
    in_interface: str | None = None,
) -> CheckResult:
    """in_interface overrides where the packet is taken to arrive.

    Deriving it from the source address is right for the firewall the traffic
    originates behind. From the second firewall in a chain onwards the packet
    arrives on the interface facing the previous one, which the source address
    says nothing about.
    """
    resolver = Resolver(config)
    family = 6 if ":" in source else 4
    in_iface = in_interface or ruleset.inbound_interface(config, source)

    translation = nat.translate_destination(config, resolver, in_iface, destination, port, protocol)
    effective_destination = translation.address if translation else destination
    effective_port = translation.port if translation else port

    result = CheckResult(
        verdict="block",
        decided_by=None,
        in_interface=in_iface,
        translated_address=translation.address if translation else None,
        translated_port=translation.port if translation else None,
    )

    for rule in ruleset.build(config, in_iface):
        matched, reason, unresolved = rule_matches(
            resolver, rule, family, source, effective_destination, effective_port, protocol
        )
        result.unresolved = result.unresolved or unresolved
        result.trace.append(TraceEntry(rule=RuleRef.of(rule), matched=matched, reason=reason))
        if not matched or not decides(rule):
            continue
        result.verdict = rule.action
        result.decided_by = RuleRef.of(rule)
        if rule.quick:
            return result

    return result


@dataclass(frozen=True)
class Region:
    addresses: list[str]
    ports: str
    verdict: str
    decided_by: RuleRef | None


@dataclass(frozen=True)
class SourceRegion:
    in_interface: str
    addresses: list[str]
    verdict: str
    decided_by: RuleRef | None


def _destination_region(resolver: Resolver, rule: FilterRule, family: int) -> RectSet:
    addresses, _ = resolver.addresses(rule.destination, family)
    ports, _ = resolver.ports(rule.destination)
    return RectSet.from_sets(addresses, ports)


def _nat_aliases(
    config: ParsedConfig, resolver: Resolver, in_iface: str, protocol: str
) -> list[tuple[IpSet, PortSet, IpSet, PortSet]]:
    """(public addresses, public ports, internal addresses, internal ports).

    A port forward means traffic aimed at the public pair actually lands on the
    internal one, so whatever the ruleset says about the internal pair is also
    true of the public pair.
    """
    out: list[tuple[IpSet, PortSet, IpSet, PortSet]] = []
    for forward in config.nat.port_forwards:
        if forward.disabled or forward.interface != in_iface:
            continue
        if not protocol_matches(forward.protocol, protocol):
            continue
        public_addresses, _ = resolver.addresses(forward.destination, 4)
        public_ports, _ = resolver.ports(forward.destination)
        if public_addresses.is_empty() or not forward.target:
            continue
        try:
            internal = IpSet.from_cidr(forward.target)
        except ValueError:
            continue
        internal_ports = (
            PortSet.parse(forward.local_port) if forward.local_port else public_ports
        )
        out.append((public_addresses, public_ports, internal, internal_ports))
    return out


def _add_public_aliases(
    regions: list[Region],
    forwarded: list[tuple[IpSet, PortSet, IpSet, PortSet]],
    family: int,
) -> list[Region]:
    if not forwarded or family != 4:
        return regions

    extra: list[Region] = []
    for region in regions:
        if region.verdict != "pass":
            continue
        covered = IpSet.empty(family)
        for cidr in region.addresses:
            covered = covered.union(IpSet.from_cidr(cidr))
        ports = PortSet.parse(region.ports)
        for public_addresses, public_ports, internal, internal_ports in forwarded:
            if covered.intersect(internal).is_empty():
                continue
            if ports.intersect(internal_ports).is_empty():
                continue
            extra.append(
                Region(
                    addresses=public_addresses.to_cidrs(),
                    ports=public_ports.to_spec(),
                    verdict=region.verdict,
                    decided_by=region.decided_by,
                )
            )
    return regions + extra


def _to_regions(area: RectSet, verdict: str, ref: RuleRef | None) -> list[Region]:
    return [
        Region(addresses=addrs.to_cidrs(), ports=ports.to_spec(), verdict=verdict, decided_by=ref)
        for addrs, ports in area.to_pairs()
        if not addrs.is_empty()
    ]


def explore_from(
    config: ParsedConfig,
    source: str,
    protocol: str = "any",
    in_interface: str | None = None,
) -> list[Region]:
    """Every destination reachable from source, as a complete partition of the space.

    Mirrors the quick / last-match rule of check() but over the whole space at
    once: a quick rule settles its slice immediately, a non-quick rule only
    stakes a provisional claim that a later quick rule can take back.
    """
    resolver = Resolver(config)
    family = 6 if ":" in source else 4
    in_iface = in_interface or ruleset.inbound_interface(config, source)

    # Destinations a port forward rewrites are reachable under their public
    # address, so the region has to be reported there too. Without this,
    # explore_from silently disagrees with check() on every published service.
    forwarded = _nat_aliases(config, resolver, in_iface, protocol)

    unsettled = RectSet.full(family)
    settled: list[Region] = []
    provisional: list[tuple[RectSet, str, RuleRef]] = []

    for rule in ruleset.build(config, in_iface):
        if not decides(rule):
            continue
        if not family_matches(rule.ipprotocol, family):
            continue
        if not protocol_matches(rule.protocol, protocol):
            continue
        source_set, _ = resolver.addresses(rule.source, family)
        if not source_set.contains_ip(source):
            continue

        slice_ = _destination_region(resolver, rule, family).intersect(unsettled)
        if slice_.is_empty():
            continue

        if rule.quick:
            settled.extend(_to_regions(slice_, rule.action, RuleRef.of(rule)))
            unsettled = unsettled.subtract(slice_)
        else:
            # A later non-quick rule wins over an earlier one, so take the
            # overlap away from every claim already staked.
            provisional = [(area.subtract(slice_), v, r) for area, v, r in provisional]
            provisional.append((slice_, rule.action, RuleRef.of(rule)))

    for area, verdict, ref in provisional:
        remaining = area.intersect(unsettled)
        if remaining.is_empty():
            continue
        settled.extend(_to_regions(remaining, verdict, ref))
        unsettled = unsettled.subtract(remaining)

    settled.extend(_to_regions(unsettled, "block", None))
    settled = _add_public_aliases(settled, forwarded, family)
    return [r for r in settled if r.addresses]


def _inbound_spaces(
    config: ParsedConfig, resolver: Resolver, family: int
) -> list[tuple[str, IpSet]]:
    """(interface, addresses that can arrive on it).

    Each enabled interface contributes its own subnet. The interface holding the
    default route additionally contributes everything outside the site, because
    that is where internet traffic arrives.
    """
    spaces: list[tuple[str, IpSet]] = []
    internal = IpSet.empty(family)
    for iface in config.interfaces:
        if not iface.enabled:
            continue
        subnet = resolver.interface_subnet(iface.name, family)
        if subnet.is_empty():
            continue
        spaces.append((iface.name, subnet))
        internal = internal.union(subnet)

    default = next(
        (g for g in config.gateways if g.default and not g.disabled and g.interface), None
    )
    edge = default.interface if default else "wan"
    outside = internal.complement()
    if not outside.is_empty() and any(name == edge for name, _ in spaces):
        spaces = [
            (name, space.union(outside) if name == edge else space) for name, space in spaces
        ]
    return spaces


def explore_to(
    config: ParsedConfig,
    destination: str,
    port: int | None,
    protocol: str = "any",
) -> list[SourceRegion]:
    """Every source that can reach destination, grouped by inbound interface."""
    resolver = Resolver(config)
    family = 6 if ":" in destination else 4
    out: list[SourceRegion] = []

    # The internet is nobody's interface subnet, so walking interfaces alone can
    # never report "this host is reachable from outside" — the single most
    # important answer this query can give.
    for iface_name, source_space in _inbound_spaces(config, resolver, family):
        subnet = source_space
        iface = config.interface_by_name(iface_name)
        if iface is None:
            continue

        unsettled = subnet
        provisional: list[tuple[IpSet, str, RuleRef]] = []
        settled: list[SourceRegion] = []

        for rule in ruleset.build(config, iface_name):
            if not decides(rule):
                continue
            if not family_matches(rule.ipprotocol, family):
                continue
            if not protocol_matches(rule.protocol, protocol):
                continue
            dest_set, _ = resolver.addresses(rule.destination, family)
            if not dest_set.contains_ip(destination):
                continue
            if port is not None:
                ports, _ = resolver.ports(rule.destination)
                if not ports.intersect(PortSet.parse(str(port))).items:
                    continue

            source_set, _ = resolver.addresses(rule.source, family)
            slice_ = source_set.intersect(unsettled)
            if slice_.is_empty():
                continue

            if rule.quick:
                settled.append(
                    SourceRegion(iface_name, slice_.to_cidrs(), rule.action, RuleRef.of(rule))
                )
                unsettled = unsettled.subtract(slice_)
            else:
                provisional = [(area.subtract(slice_), v, r) for area, v, r in provisional]
                provisional.append((slice_, rule.action, RuleRef.of(rule)))

        for area, verdict, ref in provisional:
            remaining = area.intersect(unsettled)
            if remaining.is_empty():
                continue
            settled.append(SourceRegion(iface_name, remaining.to_cidrs(), verdict, ref))
            unsettled = unsettled.subtract(remaining)

        if not unsettled.is_empty():
            settled.append(SourceRegion(iface_name, unsettled.to_cidrs(), "block", None))
        out.extend(settled)

    return out
