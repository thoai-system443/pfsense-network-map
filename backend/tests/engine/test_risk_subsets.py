"""One allowed host must not make its whole subnet read as allowed.

Reported from a real network: users get /32 addresses, one of them has a rule
out to the internet, and the exposure report claimed the object containing the
others reached the internet too. The cause is that a subject was reduced to one
representative address before being evaluated, so whatever that one address
could do was attributed to every address in the object.
"""

from app.engine import risk
from app.parser.loader import parse_config

HEAD = b"""<?xml version="1.0"?><pfsense><version>22.5</version>
<system><hostname>fw-users</hostname></system>
<interfaces>
  <wan><if>em0</if><descr>WAN</descr><enable></enable>
    <ipaddr>203.0.113.2</ipaddr><subnet>30</subnet></wan>
  <lan><if>em1</if><descr>LAN</descr><enable></enable>
    <ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan>
</interfaces>
<gateways><gateway_item><name>WANGW</name><interface>wan</interface>
  <gateway>203.0.113.1</gateway><defaultgw></defaultgw></gateway_item></gateways>"""


def build(source: bytes, destination: bytes = b"<any></any>") -> bytes:
    return (
        HEAD
        + b"""<filter><rule><type>pass</type><interface>lan</interface>
    <ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
    <source><address>"""
        + source
        + b"""</address></source>
    <destination>"""
        + destination
        + b"""</destination>
    <descr>only one host</descr></rule></filter></pfsense>"""
    )


def row(xml: bytes, label: str) -> risk.Exposure:
    return next(e for e in risk.exposures(parse_config(xml)) if e.subject.label == label)


def test_one_allowed_host_does_not_expose_the_whole_subnet():
    """10.0.0.1 may reach the internet; the other 253 addresses may not."""
    lan = row(build(b"10.0.0.1"), "LAN")
    assert lan.reaches_internet, "the exposure is real and must still be reported"
    assert lan.internet_sources == ["10.0.0.1/32"], (
        "the report has to name the part that is exposed, or a reader takes it "
        "to mean the whole 10.0.0.0/24 can reach the internet"
    )


def test_the_whole_subnet_allowed_reports_no_subset():
    """Nothing to qualify when every address in the object really can."""
    lan = row(build(b"10.0.0.0/24"), "LAN")
    assert lan.reaches_internet
    assert lan.internet_sources == []


def test_an_address_with_no_rule_is_not_reported_as_allowed():
    xml = (
        build(b"10.0.0.2").replace(
            b"</gateways>",
            b"""</gateways><aliases>
      <alias><name>USER_B</name><type>host</type><address>10.0.0.3</address>
        <descr>user B</descr></alias></aliases>""",
        )
    )
    assert not row(xml, "USER_B").reaches_internet


def test_a_host_the_probe_would_miss_is_still_found():
    """The old code ran from 10.0.0.1 only, so an exposure at .77 was invisible."""
    lan = row(build(b"10.0.0.77"), "LAN")
    assert lan.reaches_internet, "an exposed host anywhere in the subnet must be found"
    assert lan.internet_sources == ["10.0.0.77/32"]


def test_inbound_reach_names_the_part_that_is_reachable():
    xml = build(b"10.0.0.0/24", destination=b"<address>10.0.0.50</address>")
    lan = row(xml, "LAN")
    # 10.0.0.1 is in there as well, and correctly so: the implicit anti-lockout
    # rule lets LAN reach the firewall's own address. What matters is that the
    # row names addresses at all instead of reading as the whole /24.
    assert "10.0.0.50/32" in lan.inbound_internal_targets
    assert lan.inbound_internal_targets != []
    assert "10.0.0.2/32" not in lan.inbound_internal_targets
