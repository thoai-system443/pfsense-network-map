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
from app.parser.types import AddrSpec, FilterRule, ParsedConfig

FAMILY = 4
INTERNET_LABEL = "Internet"


@dataclass(frozen=True)
class Subject:
    id: str
    label: str
    kind: str
    cidrs: list[str]
    # The entries as the config declares them, each kept apart. cidrs merges
    # 10.0.0.2 and 10.0.0.3 into 10.0.0.2/31, which is right for describing the
    # object and wrong for asking about its members one at a time.
    members: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Exposure:
    """One address or network that breaks at least one of the four rules.

    The unit is the address, not the object it belongs to: an alias holding two
    hosts can have one of them wide open and the other locked down, and a row
    per object would have to pick one story for both.
    """

    subject: Subject
    cidr: str
    # Outbound: this address reaches a whole other network, on every port.
    reaches_networks_any_port: list[str] = field(default_factory=list)
    # Outbound: this address reaches the internet at all.
    reaches_internet: bool = False
    internet_ports: str = ""
    # Inbound: the internet reaches this address, on even one port.
    reachable_from_internet: bool = False
    inbound_internet_ports: str = ""
    # Inbound: another network reaches this address, on every port.
    reachable_from_networks_any_port: list[str] = field(default_factory=list)

    def breaks_a_rule(self) -> bool:
        return bool(
            self.reaches_networks_any_port
            or self.reaches_internet
            or self.reachable_from_internet
            or self.reachable_from_networks_any_port
        )


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
        cidrs = addresses.to_cidrs()
        out.append(Subject(id=zone_id, label=label, kind=kind, cidrs=cidrs, members=cidrs))

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
                members=_alias_members(resolver, alias),
            )
        )
    return out


def _sits_inside(member: IpSet, zone: IpSet) -> bool:
    """Whether an address belongs to a network.

    Traffic between two addresses on the same segment never reaches the
    firewall, so a host is not "reaching" or "reachable from" its own network
    however wide the rules are. Counting it turns every allow-any rule into a
    finding about the subnet the host already sits in.
    """
    return member.subtract(zone).is_empty()


def _alias_members(resolver: Resolver, alias) -> list[str]:
    """Each declared entry of an alias, resolved but kept separate.

    Resolving the alias as a whole and reading the result back merges adjacent
    hosts, so a list of /32 users comes out as a handful of wider prefixes and
    the per-address questions can no longer be asked.
    """
    out: list[str] = []
    for item in alias.items:
        try:
            found, _ = resolver.addresses(AddrSpec(network=item), FAMILY)
        except AliasCycleError:
            continue
        for cidr in found.to_cidrs():
            if cidr not in out:
                out.append(cidr)
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
    """Every address that breaks one of the four rules, one row each."""
    resolver = Resolver(config)
    zones = _zone_sets(config, resolver)
    internal = _internal_space(zones)
    internet = internal.complement()
    internet_probe = _probe(internet)
    allowed_from_internet = _allowed_from(config, internet_probe) if internet_probe else []

    # Keyed by the address it was run from, because the same address turns up in
    # an interface and in an alias that names a host inside it.
    outbound_cache: dict[str, list] = {}

    def allowed_from(probe: str) -> list:
        if probe not in outbound_cache:
            outbound_cache[probe] = _allowed_from(config, probe)
        return outbound_cache[probe]

    out: list[Exposure] = []
    for subject in subjects(config):
        for cidr in subject.members:
            member = IpSet.from_cidr(cidr)
            probe = _probe(member)
            if probe is None:
                continue

            reaches_networks: list[str] = []
            internet_ports = PortSet.empty()
            for region, covered in allowed_from(probe):
                ports = PortSet.parse(region.ports)
                if ports.items == [(0, MAX_PORT)]:
                    for zone_id, label, addresses in zones:
                        if zone_id == subject.id or _sits_inside(member, addresses):
                            continue
                        # The whole of another network, on the whole port range.
                        if addresses.subtract(covered).is_empty() and label not in reaches_networks:
                            reaches_networks.append(label)
                if not covered.intersect(internet).is_empty():
                    internet_ports = internet_ports.union(ports)

            inbound_internet = PortSet.empty()
            for region, covered in allowed_from_internet:
                if not covered.intersect(member).is_empty():
                    inbound_internet = inbound_internet.union(PortSet.parse(region.ports))

            reachable_from: list[str] = []
            for zone_id, label, addresses in zones:
                if zone_id == subject.id or _sits_inside(member, addresses):
                    continue
                zone_probe = _probe(addresses)
                if zone_probe is None:
                    continue
                for region, covered in allowed_from(zone_probe):
                    if PortSet.parse(region.ports).items != [(0, MAX_PORT)]:
                        continue
                    if member.subtract(covered).is_empty() and label not in reachable_from:
                        reachable_from.append(label)

            entry = Exposure(
                subject=subject,
                cidr=cidr,
                reaches_networks_any_port=reaches_networks,
                reaches_internet=not internet_ports.is_empty(),
                internet_ports=internet_ports.to_spec() if not internet_ports.is_empty() else "",
                reachable_from_internet=not inbound_internet.is_empty(),
                inbound_internet_ports=(
                    inbound_internet.to_spec() if not inbound_internet.is_empty() else ""
                ),
                reachable_from_networks_any_port=reachable_from,
            )
            if entry.breaks_a_rule():
                out.append(entry)
    return out


def port_reachability(
    config: ParsedConfig,
    port: int,
    protocol: str = "any",
    hide_internet_destinations: bool = True,
) -> list[PortAccess]:
    """Every source that reaches anything at all on this port.

    hide_internet_destinations drops only the **outbound** direction: rows whose
    destination is out on the internet. A default-allow-outbound rule otherwise
    fills the table with "LAN reaches the whole internet on 443", which buries
    the rows that matter.

    Traffic coming **in** from the internet is kept either way — that is inbound
    exposure, the most important thing this search can surface. So is anything
    internal to internal.
    """
    resolver = Resolver(config)
    zones = _zone_sets(config, resolver)
    internal = _internal_space(zones)
    wanted = PortSet.parse(str(port))

    origins = [(zone_id, label, addresses) for zone_id, label, addresses in zones]
    internet_probe = _probe(internal.complement())
    if internet_probe:
        # Always a source: internet -> something inside is exactly what an
        # operator needs to see, and hiding it would be the wrong default.
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

            destinations = region.addresses
            if hide_internet_destinations:
                reachable = _region_addresses(region).intersect(internal)
                if reachable.is_empty():
                    continue
                destinations = reachable.to_cidrs()

            out.append(
                PortAccess(
                    source_id=origin_id,
                    source_label=label,
                    destination_cidrs=destinations,
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
