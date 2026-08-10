"""Apply destination NAT before filtering, the way pfSense does.

A port forward rewrites the destination while the packet is still inbound, so
the filter rule that lets it through refers to the internal address, not the
public one. Getting this order wrong is the classic mistake when reading a
pfSense config by hand.

Outbound NAT is deliberately absent: it runs after the filter decision and so
cannot change whether a packet passes.
"""

from dataclasses import dataclass

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
