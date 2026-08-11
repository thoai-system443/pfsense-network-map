"""Apply destination NAT before filtering, the way pfSense does.

A port forward rewrites the destination while the packet is still inbound, so
the filter rule that lets it through refers to the internal address, not the
public one. Getting this order wrong is the classic mistake when reading a
pfSense config by hand.

Outbound NAT is deliberately absent: it runs after the filter decision and so
cannot change whether a packet passes.
"""

from dataclasses import dataclass

from app.engine.ipset import IpSet
from app.engine.match import protocol_matches
from app.engine.portset import PortSet
from app.engine.resolver import Resolver
from app.parser.types import ParsedConfig


@dataclass(frozen=True)
class Translation:
    address: str
    port: int | None
    via: str


def translate_destination(
    config: ParsedConfig,
    resolver: Resolver,
    in_iface: str,
    dst_ip: str,
    dst_port: int | None,
    protocol: str,
) -> Translation | None:
    family = 6 if ":" in dst_ip else 4

    for forward in config.nat.port_forwards:
        if forward.disabled or forward.interface != in_iface:
            continue
        if not protocol_matches(forward.protocol, protocol):
            continue
        addresses, _ = resolver.addresses(forward.destination, family)
        if not addresses.contains_ip(dst_ip):
            continue
        ports, _ = resolver.ports(forward.destination)
        if dst_port is not None and not ports.intersect(PortSet.parse(str(dst_port))).items:
            continue
        local_port = int(forward.local_port) if forward.local_port else dst_port
        return Translation(
            address=forward.target,
            port=local_port,
            via=f"port forward: {forward.descr or forward.target}",
        )

    for mapping in config.nat.one_to_one:
        if mapping.disabled or mapping.interface != in_iface:
            continue
        if mapping.external == dst_ip:
            return Translation(
                address=mapping.internal,
                port=dst_port,
                via=f"1:1 NAT: {mapping.descr or mapping.external}",
            )

    return None


def split_destinations(
    config: ParsedConfig,
    resolver: Resolver,
    in_iface: str,
    destinations: IpSet,
    dst_port: int | None,
    protocol: str,
) -> list[tuple[IpSet, Translation | None]]:
    """Partition a destination set by which translation it would receive.

    translate_destination answers for one address. A set can straddle several
    port forwards, so it is carved in the same rule order: the first rule that
    claims part of the set takes that part, and whatever no rule claims is
    reported untranslated. Each part therefore has one well-defined post-NAT
    destination, which is what the filter walk needs.
    """
    family = destinations.family
    remaining = destinations
    groups: list[tuple[IpSet, Translation | None]] = []

    for forward in config.nat.port_forwards:
        if remaining.is_empty():
            break
        if forward.disabled or forward.interface != in_iface:
            continue
        if not protocol_matches(forward.protocol, protocol):
            continue
        addresses, _ = resolver.addresses(forward.destination, family)
        claimed = remaining.intersect(addresses)
        if claimed.is_empty():
            continue
        ports, _ = resolver.ports(forward.destination)
        if dst_port is not None and not ports.intersect(PortSet.parse(str(dst_port))).items:
            continue
        local_port = int(forward.local_port) if forward.local_port else dst_port
        groups.append(
            (
                claimed,
                Translation(
                    address=forward.target,
                    port=local_port,
                    via=f"port forward: {forward.descr or forward.target}",
                ),
            )
        )
        remaining = remaining.subtract(claimed)

    for mapping in config.nat.one_to_one:
        if remaining.is_empty():
            break
        if mapping.disabled or mapping.interface != in_iface:
            continue
        try:
            external = IpSet.from_cidr(f"{mapping.external}/32")
        except ValueError:
            continue
        if external.family != family:
            continue
        claimed = remaining.intersect(external)
        if claimed.is_empty():
            continue
        groups.append(
            (
                claimed,
                Translation(
                    address=mapping.internal,
                    port=dst_port,
                    via=f"1:1 NAT: {mapping.descr or mapping.external}",
                ),
            )
        )
        remaining = remaining.subtract(claimed)

    if not remaining.is_empty():
        groups.append((remaining, None))
    return groups
