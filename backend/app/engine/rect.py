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


@dataclass(frozen=True, slots=True)
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
    def cross(cls, x: IpSet, y: IpSet) -> "RectSet":
        """Both axes are addresses: used for source x destination partitions."""
        return cls(
            x.family,
            [Rect(x_lo, x_hi, y_lo, y_hi) for x_lo, x_hi in x.items for y_lo, y_hi in y.items],
        )

    def to_address_pairs(self) -> list[tuple[IpSet, IpSet]]:
        """Rectangles grouped by their second axis, both read as addresses."""
        by_y: dict[tuple[int, int], list[tuple[int, int]]] = {}
        for rect in self.rects:
            by_y.setdefault((rect.p_lo, rect.p_hi), []).append((rect.a_lo, rect.a_hi))
        return [
            (IpSet(self.family, intervals.normalize(xs)), IpSet(self.family, [(y_lo, y_hi)]))
            for (y_lo, y_hi), xs in by_y.items()
        ]

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
        """Bounds computed inline rather than through Rect.intersection.

        This is the innermost loop of the whole engine — over a million pairs on
        a three thousand rule config — and two method calls per pair to answer
        "do these overlap" cost more than the arithmetic does.
        """
        self._check(other)
        out: list[Rect] = []
        for a in self.rects:
            a_lo, a_hi, ap_lo, ap_hi = a.a_lo, a.a_hi, a.p_lo, a.p_hi
            for b in other.rects:
                lo = a_lo if a_lo > b.a_lo else b.a_lo
                hi = a_hi if a_hi < b.a_hi else b.a_hi
                if lo > hi:
                    continue
                p_lo = ap_lo if ap_lo > b.p_lo else b.p_lo
                p_hi = ap_hi if ap_hi < b.p_hi else b.p_hi
                if p_lo > p_hi:
                    continue
                out.append(Rect(lo, hi, p_lo, p_hi))
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
