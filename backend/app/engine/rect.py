"""Two-dimensional sets over (address, port).

A region of traffic is a set of addresses crossed with a set of ports. Rule
evaluation over a whole space needs to subtract such regions from each other,
which a pair of one-dimensional sets cannot express. RectSet keeps a list of
pairwise-disjoint rectangles instead.
"""

from dataclasses import dataclass

from app.engine import intervals
from app.engine.ipset import IpSet
from app.engine.portset import PortSet

_MAX_ADDR = {4: 2**32 - 1, 6: 2**128 - 1}
_MAX_PORT = 65535


@dataclass(frozen=True)
class Rect:
    a_lo: int
    a_hi: int
    p_lo: int
    p_hi: int

    def overlaps(self, other: "Rect") -> bool:
        return (
            self.a_lo <= other.a_hi
            and other.a_lo <= self.a_hi
            and self.p_lo <= other.p_hi
            and other.p_lo <= self.p_hi
        )

    def intersection(self, other: "Rect") -> "Rect | None":
        if not self.overlaps(other):
            return None
        return Rect(
            max(self.a_lo, other.a_lo),
            min(self.a_hi, other.a_hi),
            max(self.p_lo, other.p_lo),
            min(self.p_hi, other.p_hi),
        )

    def minus(self, other: "Rect") -> list["Rect"]:
        """Split self into the pieces not covered by other: at most four."""
        cut = self.intersection(other)
        if cut is None:
            return [self]
        pieces: list[Rect] = []
        if self.a_lo < cut.a_lo:
            pieces.append(Rect(self.a_lo, cut.a_lo - 1, self.p_lo, self.p_hi))
        if cut.a_hi < self.a_hi:
            pieces.append(Rect(cut.a_hi + 1, self.a_hi, self.p_lo, self.p_hi))
        if self.p_lo < cut.p_lo:
            pieces.append(Rect(cut.a_lo, cut.a_hi, self.p_lo, cut.p_lo - 1))
        if cut.p_hi < self.p_hi:
            pieces.append(Rect(cut.a_lo, cut.a_hi, cut.p_hi + 1, self.p_hi))
        return pieces


@dataclass(frozen=True)
class RectSet:
    family: int
    rects: list[Rect]

    @classmethod
    def empty(cls, family: int) -> "RectSet":
        return cls(family, [])

    @classmethod
    def full(cls, family: int) -> "RectSet":
        return cls(family, [Rect(0, _MAX_ADDR[family], 0, _MAX_PORT)])

    @classmethod
    def from_sets(cls, addrs: IpSet, ports: PortSet) -> "RectSet":
        rects = [
            Rect(a_lo, a_hi, p_lo, p_hi) for a_lo, a_hi in addrs.items for p_lo, p_hi in ports.items
        ]
        return cls(addrs.family, rects)

    def _check(self, other: "RectSet") -> None:
        if self.family != other.family:
            raise ValueError(f"cannot combine family {self.family} with {other.family}")

    def subtract(self, other: "RectSet") -> "RectSet":
        self._check(other)
        current = list(self.rects)
        for cutter in other.rects:
            nxt: list[Rect] = []
            for rect in current:
                nxt.extend(rect.minus(cutter))
            current = nxt
        return RectSet(self.family, current)

    def intersect(self, other: "RectSet") -> "RectSet":
        self._check(other)
        out = [
            piece
            for a in self.rects
            for b in other.rects
            if (piece := a.intersection(b)) is not None
        ]
        return RectSet(self.family, out)

    def union(self, other: "RectSet") -> "RectSet":
        self._check(other)
        return RectSet(self.family, self.subtract(other).rects + other.rects)

    def is_empty(self) -> bool:
        return not self.rects

    def to_pairs(self) -> list[tuple[IpSet, PortSet]]:
        """Group rectangles that share a port range, so output stays readable."""
        by_ports: dict[tuple[int, int], list[tuple[int, int]]] = {}
        for rect in self.rects:
            by_ports.setdefault((rect.p_lo, rect.p_hi), []).append((rect.a_lo, rect.a_hi))
        return [
            (IpSet(self.family, intervals.normalize(addrs)), PortSet([(p_lo, p_hi)]))
            for (p_lo, p_hi), addrs in by_ports.items()
        ]
