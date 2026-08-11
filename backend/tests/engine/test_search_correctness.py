"""The six correctness bugs the 2026-08-11 audit found.

Each asserts the behaviour we want. They start marked xfail(strict=True) so a
phase that fixes one and forgets to drop the mark fails loudly instead of
quietly passing.

Plan: docs/superpowers/plans/2026-08-11-search-correctness.md
"""

from pathlib import Path

import pytest

from app.engine import fabric
from app.engine.evaluate import ANY_PROTOCOLS, check, explore_from, explore_to
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


def test_explore_to_reports_the_internet_as_a_source():
    regions = explore_to(build(PUBLISHED), "10.10.20.50", 8443, "tcp")
    passing = [r for r in regions if r.verdict == "pass"]
    assert any(touches(r.addresses, "8.8.8.8/32") for r in passing)


# --------------------------------------------------------------------------
# 4. explore must apply the same NAT check does.
# --------------------------------------------------------------------------


def test_explore_from_applies_nat_like_check():
    config = load("nat_portforward.xml")
    assert check(config, "8.8.8.8", "203.0.113.2", 443, "tcp").verdict == "pass"

    regions = explore_from(config, "8.8.8.8", "tcp")
    assert any(r.verdict == "pass" and touches(r.addresses, "203.0.113.2/32") for r in regions), (
        "check() reaches the published address but explore_from does not"
    )


# --------------------------------------------------------------------------
# 5. The chain has to follow the translated destination.
# --------------------------------------------------------------------------


def nat_chain():
    return [
        fabric.Firewall(id="fw-0", name="fw-edge", config=load("nat_chain_edge.xml")),
        fabric.Firewall(id="fw-1", name="fw-core", config=load("nat_chain_core.xml")),
    ]


def test_the_chain_follows_the_nat_target_not_the_public_address():
    result = fabric.path_check(nat_chain(), "8.8.8.8", "203.0.113.2", 443, "tcp")
    assert [hop.firewall_name for hop in result.hops] == ["fw-edge", "fw-core"]
    assert result.verdict == "block", "fw-core denies 8443, so the whole path is blocked"


# --------------------------------------------------------------------------
# 6. IPv6 is not supported across firewalls, and has to say so.
# --------------------------------------------------------------------------


def test_an_ipv6_query_says_it_is_unsupported():
    firewalls = [fabric.Firewall(id="fw-0", name="fw", config=load("routed.xml"))]
    result = fabric.path_check(firewalls, "2001:db8::1", "2001:db8::2", 443, "tcp")
    assert "IPv6" in (result.stopped_reason or "")


# --------------------------------------------------------------------------
# The invariant that let bug 4 through: it was only ever run on fixtures
# without NAT. Every fixture in the tree is checked now.
# --------------------------------------------------------------------------

ALL_FIXTURES = sorted(p.name for p in FIXTURES.glob("*.xml"))
SAMPLE_TARGETS = [
    ("192.168.1.50", "10.10.20.5", 443),
    ("192.168.1.50", "8.8.8.8", 80),
    ("8.8.8.8", "203.0.113.2", 443),
    ("10.10.20.9", "192.168.1.10", 22),
    ("10.20.5.10", "10.10.20.1", 8443),
]


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_explore_from_agrees_with_check_on_every_fixture(name):
    """explore_from is check run over the whole space. They must never differ."""
    from app.engine.portset import PortSet

    config = load(name)
    if not config.interfaces:
        pytest.skip("no interfaces to evaluate")

    for source, destination, port in SAMPLE_TARGETS:
        expected = check(config, source, destination, port, "tcp").verdict
        regions = explore_from(config, source, "tcp")
        matching = [
            r
            for r in regions
            if not PortSet.parse(r.ports).intersect(PortSet.parse(str(port))).is_empty()
            and touches(r.addresses, f"{destination}/32")
        ]
        verdicts = {r.verdict for r in matching}
        assert verdicts <= {expected}, (
            f"{name}: {source}->{destination}:{port} — check says {expected}, "
            f"explore_from says {verdicts}"
        )


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_check_regions_agrees_with_check_on_every_fixture(name):
    """The set-based walk must reduce to the point answer for a single host."""
    config = load(name)
    if not config.interfaces:
        pytest.skip("no interfaces to evaluate")

    for source, destination, port in SAMPLE_TARGETS:
        from app.engine.evaluate import check_regions

        expected = check(config, source, destination, port, "tcp")
        result = check_regions(
            config,
            IpSet.from_cidr(f"{source}/32"),
            IpSet.from_cidr(f"{destination}/32"),
            port,
            "tcp",
        )
        verdicts = {r.verdict for r in result.regions}
        assert verdicts == {expected.verdict}, (
            f"{name}: {source}->{destination}:{port} — check says {expected.verdict}, "
            f"check_regions says {verdicts}"
        )


def test_a_destination_set_spanning_two_port_forwards_is_translated_per_part():
    """203.0.113.2 and .3 forward to different hosts. One query must see both."""
    from app.engine.evaluate import check_regions

    config = load("nat_portforward.xml")
    result = check_regions(
        config,
        IpSet.from_cidr("8.8.8.8/32"),
        IpSet.from_cidr("203.0.113.0/29"),
        443,
        "tcp",
    )
    translated = {r.translated_address for r in result.regions if r.translated_address}
    assert translated == {"192.168.1.10", "192.168.1.50"}

    # And each part keeps the verdict check() gives for it on its own.
    for address in ("203.0.113.2", "203.0.113.3"):
        expected = check(config, "8.8.8.8", address, 443, "tcp").verdict
        covering = [r for r in result.regions if touches(r.destinations, f"{address}/32")]
        assert {r.verdict for r in covering} == {expected}, address


# --------------------------------------------------------------------------
# The set walk across firewalls must reduce to the point walk.
# --------------------------------------------------------------------------

CHAINS = {
    "nat-chain": ["nat_chain_edge.xml", "nat_chain_core.xml"],
    "routed-core": ["routed.xml", "core.xml"],
}


@pytest.mark.parametrize("chain", sorted(CHAINS))
def test_path_check_regions_agrees_with_path_check_for_one_host(chain):
    firewalls = [
        fabric.Firewall(id=f"fw-{i}", name=f"fw-{i}", config=load(name))
        for i, name in enumerate(CHAINS[chain])
    ]
    for source, destination, port in SAMPLE_TARGETS:
        expected = fabric.path_check(firewalls, source, destination, port, "tcp")
        regions = fabric.path_check_regions(
            firewalls,
            IpSet.from_cidr(f"{source}/32"),
            IpSet.from_cidr(f"{destination}/32"),
            port,
            "tcp",
        )
        assert {r.verdict for r in regions} == {expected.verdict}, (
            f"{chain}: {source}->{destination}:{port} — path_check says {expected.verdict}, "
            f"regions say {[r.verdict for r in regions]}"
        )
        for region in regions:
            assert [h.firewall_name for h in region.hops] == [
                h.firewall_name for h in expected.hops
            ]


def test_a_source_subnet_split_by_a_quarantine_rule_across_firewalls():
    """One blocked host inside a permitted /24 must survive the multi-hop walk."""
    firewalls = [
        fabric.Firewall(id="fw-0", name="fw-edge", config=load("nat_chain_edge.xml")),
        fabric.Firewall(id="fw-1", name="fw-core", config=load("nat_chain_core.xml")),
    ]
    regions = fabric.path_check_regions(
        firewalls,
        IpSet.from_cidr("8.8.8.0/24"),
        IpSet.from_cidr("203.0.113.2/32"),
        443,
        "tcp",
    )
    assert regions
    # The NAT target is what the second hop filters on, so the chain has to
    # reach fw-core rather than stopping at the public address.
    assert any(len(r.hops) == 2 for r in regions)
    assert all(r.hops[0].firewall_name == "fw-edge" for r in regions if r.hops)


def test_explore_from_under_any_does_not_claim_every_protocol():
    """The From tab had the same bug as check(): a tcp rule read as all protocols."""
    config = build(TCP_ONLY)
    passing = [
        r
        for r in explore_from(config, "192.168.1.9", "any")
        if r.verdict == "pass" and touches(r.addresses, "8.8.8.8/32") and "443" in r.ports
    ]
    assert passing, "the tcp region must still be reported"
    assert {r.protocol for r in passing} == {"tcp"}, (
        "a region only tcp can use must say so, not appear as a protocol-agnostic pass"
    )


def test_explore_to_under_any_tags_the_protocol_too():
    config = build(PUBLISHED)
    passing = [
        r
        for r in explore_to(config, "10.10.20.50", 8443, "any")
        if r.verdict == "pass" and touches(r.addresses, "8.8.8.8/32")
    ]
    assert passing
    assert {r.protocol for r in passing} == {"tcp"}


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_explore_from_agrees_with_check_under_any(name):
    """A region tagged for one protocol must match check() for that protocol."""
    from app.engine.portset import PortSet

    config = load(name)
    if not config.interfaces:
        pytest.skip("no interfaces to evaluate")

    for source, destination, port in SAMPLE_TARGETS:
        for region in explore_from(config, source, "any"):
            if PortSet.parse(region.ports).intersect(PortSet.parse(str(port))).is_empty():
                continue
            if not touches(region.addresses, f"{destination}/32"):
                continue
            # An untagged region claims every protocol, so check each of them.
            protocols = [region.protocol] if region.protocol else list(ANY_PROTOCOLS)
            for candidate in protocols:
                expected = check(config, source, destination, port, candidate).verdict
                assert region.verdict == expected, (
                    f"{name}: {source}->{destination}:{port}/{candidate} — "
                    f"check says {expected}, explore_from says {region.verdict}"
                )
