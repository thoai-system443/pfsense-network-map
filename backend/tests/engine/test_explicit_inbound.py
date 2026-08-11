"""Evaluating with an inbound interface chosen by the caller.

At the second firewall in a chain the packet arrives on the interface facing
the previous firewall, which has nothing to do with the subnet the original
source address belongs to. Deriving the inbound interface from the source
address — correct for a single firewall — is wrong from the second hop on.
"""

from pathlib import Path

from app.engine.evaluate import check, explore_from
from app.parser.loader import parse_config

FIXTURES = Path(__file__).parent.parent / "fixtures"


def load(name: str):
    return parse_config((FIXTURES / name).read_bytes())


def test_without_an_override_the_source_address_still_decides():
    result = check(load("routed.xml"), "192.168.1.50", "8.8.8.8", 443, "tcp")
    assert result.in_interface == "lan"
    assert result.verdict == "pass"


def test_an_override_selects_a_different_ruleset():
    """Same packet, but arriving on TRANSIT: the LAN rule no longer applies."""
    result = check(load("routed.xml"), "192.168.1.50", "8.8.8.8", 443, "tcp", in_interface="opt1")
    assert result.in_interface == "opt1"
    assert result.verdict == "block"
    assert result.decided_by is None


def test_the_override_is_reported_back():
    result = check(load("routed.xml"), "10.20.5.5", "192.168.1.10", 80, "tcp", in_interface="lan")
    assert result.in_interface == "lan"


def test_explore_honours_the_override():
    allowed = [
        region
        for region in explore_from(load("routed.xml"), "192.168.1.50", "tcp", in_interface="opt1")
        if region.verdict == "pass"
    ]
    assert allowed == []


def test_explore_without_an_override_is_unchanged():
    allowed = [
        region
        for region in explore_from(load("routed.xml"), "192.168.1.50", "tcp")
        if region.verdict == "pass"
    ]
    assert allowed != []
