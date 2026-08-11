"""The six correctness bugs the 2026-08-11 audit found.

Each asserts the behaviour we want. They start marked xfail(strict=True) so a
phase that fixes one and forgets to drop the mark fails loudly instead of
quietly passing.

Plan: docs/superpowers/plans/2026-08-11-search-correctness.md
"""

from pathlib import Path

import pytest

from app.engine import fabric
from app.engine.evaluate import check, explore_from, explore_to
from app.engine.ipset import IpSet
from app.parser.loader import parse_config

FIXTURES = Path(__file__).parent.parent / "fixtures"


def load(name: str):
    return parse_config((FIXTURES / name).read_bytes())


def build(rules_xml: str, extra: str = ""):
    return parse_config(
        f"""<?xml version="1.0"?>
<pfsense><version>22.5</version>
<system><hostname>probe</hostname></system>
<interfaces>
  <wan><if>em0</if><descr>WAN</descr><enable></enable>
    <ipaddr>203.0.113.2</ipaddr><subnet>30</subnet></wan>
  <lan><if>em1</if><descr>LAN</descr><enable></enable>
    <ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
  <opt1><if>em2</if><descr>DMZ</descr><enable></enable>
    <ipaddr>10.10.20.1</ipaddr><subnet>24</subnet></opt1>
</interfaces>
{extra}
<filter>{rules_xml}</filter>
</pfsense>""".encode()
    )


def touches(cidrs: list[str], probe: str) -> bool:
    target = IpSet.from_cidr(probe)
    return any(not IpSet.from_cidr(c).intersect(target).is_empty() for c in cidrs)


# --------------------------------------------------------------------------
# 1. A subnet is a set of addresses, not one address.
# --------------------------------------------------------------------------

SUBNET_RULES = """
  <rule><type>block</type><interface>lan</interface><ipprotocol>inet</ipprotocol>
    <protocol>tcp</protocol>
    <source><address>192.168.1.50</address></source>
    <destination><any></any><port>443</port></destination>
    <descr>Quarantine .50</descr></rule>
  <rule><type>pass</type><interface>lan</interface><ipprotocol>inet</ipprotocol>
    <protocol>tcp</protocol>
    <source><network>lan</network></source>
    <destination><any></any><port>443</port></destination>
    <descr>LAN to HTTPS</descr></rule>
"""


def test_a_single_host_in_the_subnet_is_still_answered_exactly():
    assert check(build(SUBNET_RULES), "192.168.1.50", "8.8.8.8", 443, "tcp").verdict == "block"
    assert check(build(SUBNET_RULES), "192.168.1.9", "8.8.8.8", 443, "tcp").verdict == "pass"


@pytest.mark.xfail(strict=True, reason="audit finding, not fixed yet")
def test_a_subnet_source_is_split_by_verdict():
    """192.168.1.50 is blocked, the rest of the /24 passes. Both must be reported."""
    from app.engine.evaluate import check_regions

    result = check_regions(
        build(SUBNET_RULES),
        IpSet.from_cidr("192.168.1.0/24"),
        IpSet.from_cidr("8.8.8.8/32"),
        443,
        "tcp",
    )
    blocked = [r for r in result.regions if r.verdict == "block"]
    passed = [r for r in result.regions if r.verdict == "pass"]
    assert any(touches(r.sources, "192.168.1.50") for r in blocked)
    assert any(touches(r.sources, "192.168.1.9") for r in passed)
    assert not any(touches(r.sources, "192.168.1.50") for r in passed)


# --------------------------------------------------------------------------
# 2. protocol=any must not read as "everything passes".
# --------------------------------------------------------------------------

TCP_ONLY = """
  <rule><type>pass</type><interface>lan</interface><ipprotocol>inet</ipprotocol>
    <protocol>tcp</protocol>
    <source><network>lan</network></source>
    <destination><any></any><port>443</port></destination>
    <descr>TCP 443 only</descr></rule>
"""


def test_udp_on_the_same_port_is_blocked():
    assert check(build(TCP_ONLY), "192.168.1.9", "8.8.8.8", 443, "udp").verdict == "block"


@pytest.mark.xfail(strict=True, reason="audit finding, not fixed yet")
def test_protocol_any_reports_each_protocol_separately():
    result = check(build(TCP_ONLY), "192.168.1.9", "8.8.8.8", 443, "any")
    assert result.per_protocol == {"tcp": "pass", "udp": "block", "icmp": "block"}
    assert result.verdict == "partial", "a mixed answer must not be presented as pass"


# --------------------------------------------------------------------------
# 3. explore_to has to consider the internet as a source.
# --------------------------------------------------------------------------

PUBLISHED = """
  <rule><type>pass</type><interface>wan</interface><ipprotocol>inet</ipprotocol>
    <protocol>tcp</protocol>
    <source><any></any></source>
    <destination><address>10.10.20.50</address><port>8443</port></destination>
    <descr>Published to the internet</descr></rule>
"""


@pytest.mark.xfail(strict=True, reason="audit finding, not fixed yet")
def test_explore_to_reports_the_internet_as_a_source():
    regions = explore_to(build(PUBLISHED), "10.10.20.50", 8443, "tcp")
    passing = [r for r in regions if r.verdict == "pass"]
    assert any(touches(r.addresses, "8.8.8.8/32") for r in passing)


# --------------------------------------------------------------------------
# 4. explore must apply the same NAT check does.
# --------------------------------------------------------------------------


@pytest.mark.xfail(strict=True, reason="audit finding, not fixed yet")
def test_explore_from_applies_nat_like_check():
    config = load("nat_portforward.xml")
    assert check(config, "8.8.8.8", "203.0.113.2", 443, "tcp").verdict == "pass"

    regions = explore_from(config, "8.8.8.8", "tcp")
    assert any(
        r.verdict == "pass" and touches(r.addresses, "203.0.113.2/32") for r in regions
    ), "check() reaches the published address but explore_from does not"


# --------------------------------------------------------------------------
# 5. The chain has to follow the translated destination.
# --------------------------------------------------------------------------


def nat_chain():
    return [
        fabric.Firewall(id="fw-0", name="fw-edge", config=load("nat_chain_edge.xml")),
        fabric.Firewall(id="fw-1", name="fw-core", config=load("nat_chain_core.xml")),
    ]


@pytest.mark.xfail(strict=True, reason="audit finding, not fixed yet")
def test_the_chain_follows_the_nat_target_not_the_public_address():
    result = fabric.path_check(nat_chain(), "8.8.8.8", "203.0.113.2", 443, "tcp")
    assert [hop.firewall_name for hop in result.hops] == ["fw-edge", "fw-core"]
    assert result.verdict == "block", "fw-core denies 8443, so the whole path is blocked"


# --------------------------------------------------------------------------
# 6. IPv6 is not supported across firewalls, and has to say so.
# --------------------------------------------------------------------------


@pytest.mark.xfail(strict=True, reason="audit finding, not fixed yet")
def test_an_ipv6_query_says_it_is_unsupported():
    firewalls = [fabric.Firewall(id="fw-0", name="fw", config=load("routed.xml"))]
    result = fabric.path_check(firewalls, "2001:db8::1", "2001:db8::2", 443, "tcp")
    assert "IPv6" in (result.stopped_reason or "")
