"""Sets of IP addresses, represented as integer intervals within one family.

IPv4 and IPv6 live in separate spaces. Any operation mixing the two raises,
because comparing their integer representations is always a bug.
"""

import ipaddress
from dataclasses import dataclass

from app.engine import intervals
from app.engine.intervals import Interval

_MAX = {4: 2**32 - 1, 6: 2**128 - 1}


@dataclass(frozen=True)
class IpSet:
    family: int
    items: list[Interval]

    @classmethod
    def empty(cls, family: int) -> "IpSet":
        return cls(family, [])

    @classmethod
    def full(cls, family: int) -> "IpSet":
        return cls(family, [(0, _MAX[family])])

    @classmethod
    def from_cidr(cls, value: str) -> "IpSet":
        net = ipaddress.ip_network(value.strip(), strict=False)
        return cls(net.version, [(int(net.network_address), int(net.broadcast_address))])

    def _check(self, other: "IpSet") -> None:
        if self.family != other.family:
            raise ValueError(f"cannot combine family {self.family} with {other.family}")

    def union(self, other: "IpSet") -> "IpSet":
        self._check(other)
        return IpSet(self.family, intervals.union(self.items, other.items))

    def intersect(self, other: "IpSet") -> "IpSet":
        self._check(other)
        return IpSet(self.family, intervals.intersect(self.items, other.items))

    def subtract(self, other: "IpSet") -> "IpSet":
        self._check(other)
        return IpSet(self.family, intervals.subtract(self.items, other.items))

    def complement(self) -> "IpSet":
        return IpSet.full(self.family).subtract(self)

    def is_empty(self) -> bool:
        return not self.items

    def contains_ip(self, value: str) -> bool:
        addr = ipaddress.ip_address(value)
        if addr.version != self.family:
            return False
        n = int(addr)
        return any(lo <= n <= hi for lo, hi in self.items)

    def to_cidrs(self) -> list[str]:
        out: list[str] = []
        for lo, hi in self.items:
            first = ipaddress.ip_address(lo)
            last = ipaddress.ip_address(hi)
            out.extend(str(net) for net in ipaddress.summarize_address_range(first, last))
        return out
