"""Sets of TCP/UDP port numbers."""

from dataclasses import dataclass

from app.engine import intervals
from app.engine.intervals import Interval

MAX_PORT = 65535


@dataclass(frozen=True)
class PortSet:
    items: list[Interval]

    @classmethod
    def empty(cls) -> "PortSet":
        return cls([])

    @classmethod
    def full(cls) -> "PortSet":
        return cls([(0, MAX_PORT)])

    @classmethod
    def parse(cls, spec: str) -> "PortSet":
        found: list[Interval] = []
        for part in spec.replace(":", "-").split(","):
            part = part.strip()
            if not part:
                continue
            lo_text, _, hi_text = part.partition("-")
            lo = int(lo_text)
            hi = int(hi_text) if hi_text else lo
            if not (0 <= lo <= MAX_PORT and 0 <= hi <= MAX_PORT):
                raise ValueError(f"port out of range: {part}")
            found.append((lo, hi))
        return cls(intervals.normalize(found))

    def union(self, other: "PortSet") -> "PortSet":
        return PortSet(intervals.union(self.items, other.items))

    def intersect(self, other: "PortSet") -> "PortSet":
        return PortSet(intervals.intersect(self.items, other.items))

    def subtract(self, other: "PortSet") -> "PortSet":
        return PortSet(intervals.subtract(self.items, other.items))

    def is_empty(self) -> bool:
        return not self.items

    def to_spec(self) -> str:
        if not self.items:
            return "none"
        if self.items == [(0, MAX_PORT)]:
            return "any"
        return ",".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in self.items)
