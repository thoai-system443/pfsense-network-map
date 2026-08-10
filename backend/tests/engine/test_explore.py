from pathlib import Path

from app.engine.evaluate import check, explore_from, explore_to
from app.engine.ipset import IpSet
from app.engine.portset import PortSet
from app.engine.rect import RectSet
from app.parser.loader import parse_config

FIXTURES = Path(__file__).parent.parent / "fixtures"


def load(name: str):
    return parse_config((FIXTURES / name).read_bytes())


def coverage(regions) -> RectSet:
    total = RectSet.empty(4)
    for region in regions:
        addrs = IpSet.empty(4)
        for cidr in region.addresses:
            addrs = addrs.union(IpSet.from_cidr(cidr))
        total = total.union(RectSet.from_sets(addrs, PortSet.parse(region.ports)))
    return total


def test_regions_cover_the_entire_space():
    regions = explore_from(load("basic.xml"), "192.168.1.50", "tcp")
    assert RectSet.full(4).subtract(coverage(regions)).is_empty()


def test_regions_do_not_overlap_each_other():
    regions = explore_from(load("basic.xml"), "192.168.1.50", "tcp")
    seen = RectSet.empty(4)
    for region in regions:
        piece = coverage([region])
        assert piece.intersect(seen).is_empty()
        seen = seen.union(piece)


def test_https_to_anywhere_is_allowed():
    regions = explore_from(load("basic.xml"), "192.168.1.50", "tcp")
    allowed = [r for r in regions if r.verdict == "pass"]
    assert any(r.ports == "443" and r.addresses == ["0.0.0.0/0"] for r in allowed)


def test_everything_else_is_blocked():
    regions = explore_from(load("basic.xml"), "192.168.1.50", "tcp")
    assert any(r.verdict == "block" for r in regions)


def test_explore_agrees_with_point_check_on_sampled_points():
    """explore_from must be the same function as check, run over a whole space."""
    config = load("floating.xml")
    regions = explore_from(config, "192.168.1.50", "tcp")
    for destination, port in [
        ("10.10.20.5", 445),
        ("10.10.20.5", 23),
        ("8.8.8.8", 445),
        ("8.8.8.8", 9999),
    ]:
        expected = check(config, "192.168.1.50", destination, port, "tcp").verdict
        matching = [
            r
            for r in regions
            if PortSet.parse(r.ports).intersect(PortSet.parse(str(port))).items
            and any(IpSet.from_cidr(c).contains_ip(destination) for c in r.addresses)
        ]
        assert len(matching) == 1
        assert matching[0].verdict == expected


def test_explore_agrees_with_point_check_on_the_not_flag_fixture():
    config = load("not_flag.xml")
    regions = explore_from(config, "192.168.1.50", "tcp")
    for destination, port in [("10.10.20.5", 80), ("8.8.8.8", 80), ("192.168.1.9", 22)]:
        expected = check(config, "192.168.1.50", destination, port, "tcp").verdict
        matching = [
            r
            for r in regions
            if PortSet.parse(r.ports).intersect(PortSet.parse(str(port))).items
            and any(IpSet.from_cidr(c).contains_ip(destination) for c in r.addresses)
        ]
        assert len(matching) == 1
        assert matching[0].verdict == expected


def test_explore_to_reports_which_interface_traffic_enters_on():
    regions = explore_to(load("basic.xml"), "8.8.8.8", 443, "tcp")
    assert any(r.in_interface == "lan" and r.verdict == "pass" for r in regions)


def test_explore_to_reports_blocked_sources():
    regions = explore_to(load("basic.xml"), "8.8.8.8", 23, "tcp")
    assert all(r.verdict != "pass" for r in regions)
