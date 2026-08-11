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
) -> CheckResult:
    resolver = Resolver(config)
    family = 6 if ":" in source else 4
    in_iface = ruleset.inbound_interface(config, source)

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


def _to_regions(area: RectSet, verdict: str, ref: RuleRef | None) -> list[Region]:
    return [
        Region(addresses=addrs.to_cidrs(), ports=ports.to_spec(), verdict=verdict, decided_by=ref)
        for addrs, ports in area.to_pairs()
        if not addrs.is_empty()
    ]


def explore_from(config: ParsedConfig, source: str, protocol: str = "any") -> list[Region]:
    """Every destination reachable from source, as a complete partition of the space.

    Mirrors the quick / last-match rule of check() but over the whole space at
    once: a quick rule settles its slice immediately, a non-quick rule only
    stakes a provisional claim that a later quick rule can take back.
    """
    resolver = Resolver(config)
    family = 6 if ":" in source else 4
    in_iface = ruleset.inbound_interface(config, source)

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
    return [r for r in settled if r.addresses]


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

    for iface in config.interfaces:
        if not iface.enabled:
            continue
        subnet = resolver.interface_subnet(iface.name, family)
        if subnet.is_empty():
            continue

        unsettled = subnet
        provisional: list[tuple[IpSet, str, RuleRef]] = []
        settled: list[SourceRegion] = []

        for rule in ruleset.build(config, iface.name):
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
                    SourceRegion(iface.name, slice_.to_cidrs(), rule.action, RuleRef.of(rule))
                )
                unsettled = unsettled.subtract(slice_)
            else:
                provisional = [(area.subtract(slice_), v, r) for area, v, r in provisional]
                provisional.append((slice_, rule.action, RuleRef.of(rule)))

        for area, verdict, ref in provisional:
            remaining = area.intersect(unsettled)
            if remaining.is_empty():
                continue
            settled.append(SourceRegion(iface.name, remaining.to_cidrs(), verdict, ref))
            unsettled = unsettled.subtract(remaining)

        if not unsettled.is_empty():
            settled.append(SourceRegion(iface.name, unsettled.to_cidrs(), "block", None))
        out.extend(settled)

    return out
