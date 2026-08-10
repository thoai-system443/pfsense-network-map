import pytest

from app.engine.ipset import IpSet


def test_from_cidr_v4_covers_whole_block():
    s = IpSet.from_cidr("10.0.0.0/24")
    assert s.family == 4
    assert s.items == [(167772160, 167772415)]


def test_from_bare_ip_is_single_address():
    s = IpSet.from_cidr("192.168.1.10")
    assert s.items == [(3232235786, 3232235786)]


def test_from_cidr_v6_sets_family_six():
    assert IpSet.from_cidr("2001:db8::/32").family == 6


def test_full_v4_spans_entire_space():
    assert IpSet.full(4).items == [(0, 2**32 - 1)]


def test_complement_of_full_is_empty():
    assert IpSet.full(4).complement().is_empty()


def test_subtract_produces_disjoint_cidrs():
    s = IpSet.from_cidr("10.0.0.0/24").subtract(IpSet.from_cidr("10.0.0.128/25"))
    assert s.to_cidrs() == ["10.0.0.0/25"]


def test_to_cidrs_splits_non_aligned_range():
    s = IpSet.from_cidr("10.0.0.0/24").subtract(IpSet.from_cidr("10.0.0.0/32"))
    assert s.to_cidrs() == [
        "10.0.0.1/32",
        "10.0.0.2/31",
        "10.0.0.4/30",
        "10.0.0.8/29",
        "10.0.0.16/28",
        "10.0.0.32/27",
        "10.0.0.64/26",
        "10.0.0.128/25",
    ]


def test_mixing_families_is_rejected():
    with pytest.raises(ValueError, match="family"):
        IpSet.from_cidr("10.0.0.0/8").union(IpSet.from_cidr("2001:db8::/32"))
