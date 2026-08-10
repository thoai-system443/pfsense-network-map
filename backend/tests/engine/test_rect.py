from app.engine.ipset import IpSet
from app.engine.portset import PortSet
from app.engine.rect import Rect, RectSet


def test_full_is_one_rect_spanning_everything():
    full = RectSet.full(4)
    assert full.rects == [Rect(0, 2**32 - 1, 0, 65535)]


def test_from_sets_builds_cross_product():
    addrs = IpSet.from_cidr("10.0.0.0/31")
    ports = PortSet.parse("80,443")
    rs = RectSet.from_sets(addrs, ports)
    assert len(rs.rects) == 2


def test_subtract_middle_leaves_four_pieces():
    outer = RectSet(4, [Rect(0, 100, 0, 100)])
    inner = RectSet(4, [Rect(40, 60, 40, 60)])
    assert len(outer.subtract(inner).rects) == 4


def test_subtract_everything_gives_empty():
    outer = RectSet(4, [Rect(0, 100, 0, 100)])
    assert outer.subtract(RectSet(4, [Rect(0, 100, 0, 100)])).is_empty()


def test_subtract_disjoint_changes_nothing():
    outer = RectSet(4, [Rect(0, 10, 0, 10)])
    other = RectSet(4, [Rect(50, 60, 50, 60)])
    assert outer.subtract(other).rects == outer.rects


def test_remainder_does_not_intersect_what_was_removed():
    outer = RectSet(4, [Rect(0, 100, 0, 100)])
    inner = RectSet(4, [Rect(40, 60, 40, 60)])
    assert outer.subtract(inner).intersect(inner).is_empty()


def test_removed_plus_remainder_covers_the_original():
    outer = RectSet(4, [Rect(0, 100, 0, 100)])
    inner = RectSet(4, [Rect(40, 60, 40, 60)])
    remainder = outer.subtract(inner)
    covered = remainder.union(outer.intersect(inner))
    assert outer.subtract(covered).is_empty()


def test_to_pairs_returns_addresses_and_ports():
    rs = RectSet.from_sets(IpSet.from_cidr("10.0.0.0/24"), PortSet.parse("443"))
    pairs = rs.to_pairs()
    assert pairs[0][0].to_cidrs() == ["10.0.0.0/24"]
    assert pairs[0][1].to_spec() == "443"
