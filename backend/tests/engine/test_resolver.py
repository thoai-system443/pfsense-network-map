from pathlib import Path

import pytest

from app.engine.resolver import AliasCycleError, Resolver
from app.parser.loader import parse_config
from app.parser.types import AddrSpec

FIXTURES = Path(__file__).parent.parent / "fixtures"


def resolver(name: str) -> Resolver:
    return Resolver(parse_config((FIXTURES / name).read_bytes()))


def test_any_covers_whole_space():
    found, unresolved = resolver("basic.xml").addresses(AddrSpec(any=True), 4)
    assert found.to_cidrs() == ["0.0.0.0/0"]
    assert unresolved is False


def test_interface_name_resolves_to_its_subnet():
    found, _ = resolver("basic.xml").addresses(AddrSpec(network="lan"), 4)
    assert found.to_cidrs() == ["192.168.1.0/24"]


def test_interface_ip_keyword_resolves_to_single_address():
    found, _ = resolver("basic.xml").addresses(AddrSpec(network="lanip"), 4)
    assert found.to_cidrs() == ["192.168.1.1/32"]


def test_self_resolves_to_every_interface_address():
    found, _ = resolver("basic.xml").addresses(AddrSpec(network="(self)"), 4)
    assert set(found.to_cidrs()) == {"192.168.1.1/32", "203.0.113.2/32"}


def test_literal_cidr_resolves_to_itself():
    found, _ = resolver("basic.xml").addresses(AddrSpec(address="10.0.0.0/8"), 4)
    assert found.to_cidrs() == ["10.0.0.0/8"]


def test_alias_expands_to_its_members():
    """Adjacent members collapse: .10 and .11 are the minimal cover 10/31."""
    found, _ = resolver("basic.xml").addresses(AddrSpec(address="WEB_SERVERS"), 4)
    assert found.to_cidrs() == ["192.168.1.10/31"]
    assert found.contains_ip("192.168.1.10")
    assert found.contains_ip("192.168.1.11")
    assert not found.contains_ip("192.168.1.12")


def test_nested_alias_expands_through_three_levels():
    found, _ = resolver("alias_nested.xml").addresses(AddrSpec(address="ALL_SERVERS"), 4)
    assert found.to_cidrs() == [
        "192.168.1.20/31",
        "192.168.1.30/32",
        "192.168.1.40/32",
    ]


def test_alias_cycle_raises_with_the_chain():
    with pytest.raises(AliasCycleError) as info:
        resolver("alias_nested.xml").addresses(AddrSpec(address="LOOP_A"), 4)
    assert "LOOP_A" in info.value.chain and "LOOP_B" in info.value.chain


def test_not_flag_inverts_the_set():
    found, _ = resolver("basic.xml").addresses(AddrSpec(network="lan", not_=True), 4)
    assert "192.168.1.0/24" not in found.to_cidrs()
    assert found.contains_ip("8.8.8.8")


def test_urltable_alias_is_empty_and_flagged_unresolved():
    found, unresolved = resolver("unresolvable_alias.xml").addresses(
        AddrSpec(address="BLOCKLIST"), 4
    )
    assert found.is_empty()
    assert unresolved is True


def test_missing_port_means_all_ports():
    found, _ = resolver("basic.xml").ports(AddrSpec())
    assert found.to_spec() == "any"


def test_port_alias_expands_including_ranges():
    found, _ = resolver("alias_nested.xml").ports(AddrSpec(port="MGMT_PORTS"))
    assert found.to_spec() == "22,3389,5900-5910"


def test_ipv6_query_against_ipv4_only_interface_is_empty():
    found, _ = resolver("basic.xml").addresses(AddrSpec(network="lan"), 6)
    assert found.is_empty()


def test_expand_alias_by_name_is_public():
    found, _ = resolver("alias_nested.xml").expand_alias("TIER_TWO", 4)
    assert found.to_cidrs() == ["192.168.1.20/31", "192.168.1.30/32"]


def test_expand_alias_ports_by_name_is_public():
    found, _ = resolver("alias_nested.xml").expand_alias_ports("MGMT_PORTS")
    assert found.to_spec() == "22,3389,5900-5910"
