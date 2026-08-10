import pytest

from app.engine.portset import PortSet


def test_parse_single_port():
    assert PortSet.parse("443").items == [(443, 443)]


def test_parse_range_with_dash():
    assert PortSet.parse("1000-2000").items == [(1000, 2000)]


def test_parse_range_with_colon():
    assert PortSet.parse("1000:2000").items == [(1000, 2000)]


def test_parse_comma_list_merges():
    assert PortSet.parse("80,443,8080").items == [(80, 80), (443, 443), (8080, 8080)]


def test_full_covers_all_ports():
    assert PortSet.full().items == [(0, 65535)]


def test_to_spec_renders_single_and_range():
    assert PortSet.parse("80,1000-2000").to_spec() == "80,1000-2000"


def test_to_spec_of_full_is_any():
    assert PortSet.full().to_spec() == "any"


def test_to_spec_of_empty_is_none_marker():
    assert PortSet.empty().to_spec() == "none"


def test_parse_rejects_out_of_range():
    with pytest.raises(ValueError, match="port"):
        PortSet.parse("70000")
