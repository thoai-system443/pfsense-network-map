"""What counts as "the internet" for the exposure report.

The internet is defined by exclusion: everything outside the networks this tool
knows about. That makes the definition only as good as the list of known
networks, and two kinds of network were missing from it — a branch office
behind an internal static route, and the subnets of a second firewall loaded
into the same workspace. Both were being reported as internet exposure.
"""

from app.engine import risk
from app.engine.ipset import IpSet
from app.parser.loader import parse_config

HEAD = b"""<?xml version="1.0"?><pfsense><version>22.5</version>
<system><hostname>fw</hostname></system>
<interfaces>
  <wan><if>em0</if><descr>WAN</descr><enable></enable>
    <ipaddr>203.0.113.2</ipaddr><subnet>30</subnet></wan>
  <lan><if>em1</if><descr>LAN</descr><enable></enable>
    <ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan>
</interfaces>
<gateways>
  <gateway_item><name>WANGW</name><interface>wan</interface>
    <gateway>203.0.113.1</gateway><defaultgw></defaultgw></gateway_item>
  <gateway_item><name>ROUTER</name><interface>lan</interface>
    <gateway>10.0.0.254</gateway></gateway_item>
</gateways>
<aliases><alias><name>U</name><type>host</type><address>10.0.0.5</address></alias></aliases>"""

TO_BRANCH = b"""<filter><rule><type>pass</type><interface>lan</interface>
  <ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
  <source><address>10.0.0.5</address></source>
  <destination><address>192.168.50.10</address><port>443</port></destination>
  <descr>to the branch</descr></rule></filter></pfsense>"""


def build(routes: bytes) -> bytes:
    return HEAD + b"<staticroutes>" + routes + b"</staticroutes>" + TO_BRANCH


def reaches_internet(xml: bytes, also_internal: IpSet | None = None) -> bool:
    rows = risk.exposures(parse_config(xml), also_internal=also_internal)
    row = next((e for e in rows if e.cidr == "10.0.0.5/32"), None)
    return bool(row and row.reaches_internet)


INTERNAL_ROUTE = b"""<route><network>192.168.50.0/24</network>
  <gateway>ROUTER</gateway><descr>branch office</descr></route>"""

ROUTE_OUT_THE_WAN = b"""<route><network>192.168.50.0/24</network>
  <gateway>WANGW</gateway><descr>via the ISP</descr></route>"""


def test_a_network_behind_an_internal_static_route_is_not_the_internet():
    assert reaches_internet(build(INTERNAL_ROUTE)) is False


def test_a_static_route_out_of_the_wan_is_still_the_internet():
    """The packet leaves the site, whatever the destination looks like."""
    assert reaches_internet(build(ROUTE_OUT_THE_WAN)) is True


def test_without_any_route_the_branch_still_counts_as_internet():
    """Nothing in the config says this network exists, so the tool cannot claim it."""
    assert reaches_internet(build(b"")) is True


def test_a_disabled_route_does_not_make_a_network_internal():
    disabled = INTERNAL_ROUTE.replace(b"<descr>", b"<disabled></disabled><descr>")
    assert reaches_internet(build(disabled)) is True


def test_a_subnet_on_another_loaded_firewall_is_not_the_internet():
    other = IpSet.from_cidr("192.168.50.0/24")
    assert reaches_internet(build(b""), also_internal=other) is False


def test_internal_space_reports_what_a_config_knows_about():
    space = risk.internal_space(parse_config(build(INTERNAL_ROUTE)))
    assert not space.intersect(IpSet.from_cidr("192.168.50.0/24")).is_empty()
    assert not space.intersect(IpSet.from_cidr("10.0.0.0/24")).is_empty()
    assert space.intersect(IpSet.from_cidr("8.8.8.8/32")).is_empty()
