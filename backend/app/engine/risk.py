"""Turn the reachability engine into risk findings.

Everything here is derived from evaluate.explore_from, so a finding can never
disagree with what the Search page reports for the same traffic. Nothing new
about pf semantics is decided in this module.
"""

import ipaddress
from dataclasses import dataclass, field

from app.engine import ruleset
from app.engine.evaluate import RuleRef, explore_from
from app.engine.ipset import IpSet
from app.engine.match import family_matches, protocol_matches
from app.engine.portset import MAX_PORT, PortSet
from app.engine.resolver import AliasCycleError, Resolver
from app.parser.types import FilterRule, ParsedConfig

FAMILY = 4
INTERNET_LABEL = "Internet"


@dataclass(frozen=True)
class Subject:
    id: str
    label: str
    kind: str
    cidrs: list[str]


@dataclass(frozen=True)
class Exposure:
    subject: Subject
    reaches_other_subnets_any_port: list[str] = field(default_factory=list)
    reaches_internet: bool = False
    internet_ports: str = ""
    reachable_from_all_internal: bool = False
    inbound_internal_ports: str = ""
    reachable_from_internet: bool = False
    inbound_internet_ports: str = ""


@dataclass(frozen=True)
class PortAccess:
    source_id: str
    source_label: str
    destination_cidrs: list[str]
    ports: str
    rule: RuleRef | None


@dataclass(frozen=True)
class DenyAllFinding:
    kind: str
    interface: str
    rule: RuleRef
    detail: str


def _probe(addresses: IpSet) -> str | None:
    """A representative address inside a set, to run the engine from."""
    if not addresses.items:
        return None
    lo, hi = addresses.items[0]
    return str(ipaddress.ip_address(lo + 1 if lo < hi else lo))


def _zone_sets(config: ParsedConfig, resolver: Resolver) -> list[tuple[str, str, IpSet]]:
    """(id, label, addresses) for each enabled interface and VPN tunnel."""
    zones: list[tuple[str, str, IpSet]] = []
    for iface in config.interfaces:
        if not iface.enabled:
            continue
        subnet = resolver.interface_subnet(iface.name, FAMILY)
        if not subnet.is_empty():
            zones.append((iface.name, iface.descr, subnet))

    for index, tunnel in enumerate(config.vpn.tunnels):
        reachable = IpSet.empty(FAMILY)
        for cidr in [tunnel.tunnel_network, *tunnel.remote_networks]:
            if not cidr:
                continue
            try:
                part = IpSet.from_cidr(cidr)
            except ValueError:
                continue
            if part.family == FAMILY:
                reachable = reachable.union(part)
        if not reachable.is_empty():
            zones.append((f"tunnel-{index}", tunnel.descr or tunnel.kind, reachable))
    return zones


def _internal_space(zones: list[tuple[str, str, IpSet]]) -> IpSet:
    space = IpSet.empty(FAMILY)
    for _, _, addresses in zones:
        space = space.union(addresses)
    return space


def subjects(config: ParsedConfig) -> list[Subject]:
    """Everything worth asking the four exposure questions about."""
    resolver = Resolver(config)
    out: list[Subject] = []

    for zone_id, label, addresses in _zone_sets(config, resolver):
        kind = "tunnel" if zone_id.startswith("tunnel-") else "interface"
        out.append(Subject(id=zone_id, label=label, kind=kind, cidrs=addresses.to_cidrs()))

    for alias in config.aliases:
        if alias.type not in {"host", "network"}:
            continue
        try:
            addresses, _ = resolver.expand_alias(alias.name, FAMILY)
        except AliasCycleError:
            continue
        if addresses.is_empty():
            continue
        out.append(
            Subject(
                id=f"alias:{alias.name}",
                label=alias.name,
                kind="alias",
                cidrs=addresses.to_cidrs(),
            )
        )
    return out


def _subject_set(subject: Subject) -> IpSet:
    addresses = IpSet.empty(FAMILY)
    for cidr in subject.cidrs:
        addresses = addresses.union(IpSet.from_cidr(cidr))
    return addresses


def _allowed_from(config: ParsedConfig, probe: str) -> list:
    """Allowed regions, each paired with its addresses already turned into a set.

    The set is built once here rather than per subject: exposures compares every
    region against every zone and every subject, and rebuilding it each time was
    the dominant cost of the whole risk report.
    """
    return [
        (region, _region_addresses(region))
        for region in explore_from(config, probe, "any")
        if region.verdict == "pass"
    ]


def _region_addresses(region) -> IpSet:
    addresses = IpSet.empty(FAMILY)
    for cidr in region.addresses:
        addresses = addresses.union(IpSet.from_cidr(cidr))
    return addresses


def exposures(config: ParsedConfig) -> list[Exposure]:
    resolver = Resolver(config)
    zones = _zone_sets(config, resolver)
    internal = _internal_space(zones)
    internet = internal.complement()
    internet_probe = _probe(internet)

    # Computed once and reused: explore_from is the expensive part.
    allowed_by_zone = {
        zone_id: _allowed_from(config, probe)
        for zone_id, _, addresses in zones
        if (probe := _probe(addresses))
    }
    allowed_from_internet = _allowed_from(config, internet_probe) if internet_probe else []

    out: list[Exposure] = []
    for subject in subjects(config):
        target = _subject_set(subject)
        own_probe = _probe(target)
        outbound = allowed_by_zone.get(subject.id) or (
            _allowed_from(config, own_probe) if own_probe else []
        )

        wide_open: list[str] = []
        internet_ports = PortSet.empty()
        for region, covered in outbound:
            ports = PortSet.parse(region.ports)
            every_port = ports.items == [(0, MAX_PORT)]
            for zone_id, label, addresses in zones:
                if zone_id == subject.id or covered.intersect(addresses).is_empty():
                    continue
                if every_port and label not in wide_open:
                    wide_open.append(label)
            if not covered.intersect(internet).is_empty():
                internet_ports = internet_ports.union(ports)

        inbound_internet = PortSet.empty()
        for region, covered in allowed_from_internet:
            if not covered.intersect(target).is_empty():
                inbound_internet = inbound_internet.union(PortSet.parse(region.ports))

        reaching_zones: set[str] = set()
        inbound_internal = PortSet.empty()
        for zone_id, _, _ in zones:
            for region, covered in allowed_by_zone.get(zone_id, []):
                if covered.intersect(target).is_empty():
                    continue
                reaching_zones.add(zone_id)
                inbound_internal = inbound_internal.union(PortSet.parse(region.ports))

        # "From any internal source" means every zone other than the subject's
        # own can get in. The internet is deliberately not one of them.
        others = {zone_id for zone_id, _, _ in zones if zone_id != subject.id}
        out.append(
            Exposure(
                subject=subject,
                reaches_other_subnets_any_port=wide_open,
                reaches_internet=not internet_ports.is_empty(),
                internet_ports=internet_ports.to_spec() if not internet_ports.is_empty() else "",
                reachable_from_all_internal=bool(others) and others <= reaching_zones,
                inbound_internal_ports=(
                    inbound_internal.to_spec() if not inbound_internal.is_empty() else ""
                ),
                reachable_from_internet=not inbound_internet.is_empty(),
                inbound_internet_ports=(
                    inbound_internet.to_spec() if not inbound_internet.is_empty() else ""
                ),
            )
        )
    return out


def port_reachability(config: ParsedConfig, port: int, protocol: str = "any") -> list[PortAccess]:
    """Every source that reaches anything at all on this port."""
    resolver = Resolver(config)
    zones = _zone_sets(config, resolver)
    internal = _internal_space(zones)
    wanted = PortSet.parse(str(port))

    origins = [(zone_id, label, addresses) for zone_id, label, addresses in zones]
    internet_probe = _probe(internal.complement())
    if internet_probe:
        origins.append(("internet", INTERNET_LABEL, internal.complement()))

    out: list[PortAccess] = []
    for origin_id, label, addresses in origins:
        probe = internet_probe if origin_id == "internet" else _probe(addresses)
        if probe is None:
            continue
        for region in explore_from(config, probe, protocol):
            if region.verdict != "pass":
                continue
            if PortSet.parse(region.ports).intersect(wanted).is_empty():
                continue
            out.append(
                PortAccess(
                    source_id=origin_id,
                    source_label=label,
                    destination_cidrs=region.addresses,
                    ports=region.ports,
                    rule=region.decided_by,
                )
            )
    return out


def _is_block_all(resolver: Resolver, rule: FilterRule) -> bool:
    if rule.action not in {"block", "reject"}:
        return False
    if not protocol_matches(rule.protocol, "any"):
        return False
    source, _ = resolver.addresses(rule.source, FAMILY)
    destination, _ = resolver.addresses(rule.destination, FAMILY)
    if source != IpSet.full(FAMILY) or destination != IpSet.full(FAMILY):
        return False
    ports, _ = resolver.ports(rule.destination)
    return ports.items == [(0, MAX_PORT)]


def deny_all_audit(config: ParsedConfig) -> list[DenyAllFinding]:
    """Check that each interface's block-all rules actually stop traffic.

    Two ways they do not. A floating block-all without the quick flag records a
    verdict but keeps evaluating, so any later interface rule overrides it. And
    once a block-all with quick is in place, every rule after it is dead — the
    access an operator believes they granted does not exist.
    """
    resolver = Resolver(config)
    findings: list[DenyAllFinding] = []

    interfaces = [iface.name for iface in config.interfaces if iface.enabled]
    for name in interfaces:
        rules = ruleset.build(config, name)
        terminal_seen = False
        for rule in rules:
            if rule.synthetic:
                continue
            if terminal_seen:
                findings.append(
                    DenyAllFinding(
                        kind="unreachable-rule",
                        interface=name,
                        rule=RuleRef.of(rule),
                        detail=(
                            "a block-all with the quick flag is evaluated earlier on this "
                            "interface, so this rule is never reached"
                        ),
                    )
                )
                continue
            if not _is_block_all(resolver, rule):
                continue
            if rule.quick:
                terminal_seen = True
                continue
            later_pass = any(
                other.action == "pass"
                for other in rules[rules.index(rule) + 1 :]
                if family_matches(other.ipprotocol, FAMILY)
            )
            if later_pass:
                findings.append(
                    DenyAllFinding(
                        kind="block-all-not-quick",
                        interface=name,
                        rule=RuleRef.of(rule),
                        detail=(
                            "this block-all has no quick flag, so evaluation continues and a "
                            "later rule on this interface can override it"
                        ),
                    )
                )
    return findings
