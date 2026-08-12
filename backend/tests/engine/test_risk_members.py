"""Exposure is reported per IP/network, not per object.

An object can hold several addresses, and they do not have to share a fate. A
row therefore names the address it is about, and only addresses that break one
of the four rules are reported at all.
"""

from app.engine import risk
from app.parser.loader import parse_config

HEAD = b"""<?xml version="1.0"?><pfsense><version>22.5</version>
<system><hostname>fw</hostname></system>
<interfaces>
  <wan><if>em0</if><descr>WAN</descr><enable></enable>
    <ipaddr>203.0.113.2</ipaddr><subnet>30</subnet></wan>
  <lan><if>em1</if><descr>LAN</descr><enable></enable>
    <ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan>
  <opt1><if>em2</if><descr>DMZ</descr><enable></enable>
    <ipaddr>10.10.20.1</ipaddr><subnet>24</subnet></opt1>
</interfaces>
<gateways><gateway_item><name>GW</name><interface>wan</interface>
  <gateway>203.0.113.1</gateway><defaultgw></defaultgw></gateway_item></gateways>"""


def build(aliases: bytes = b"", rules: bytes = b"") -> bytes:
    return HEAD + b"<aliases>" + aliases + b"</aliases><filter>" + rules + b"</filter></pfsense>"


def findings(xml: bytes) -> dict[str, risk.Exposure]:
    """Keyed by the address each finding is about."""
    return {entry.cidr: entry for entry in risk.exposures(parse_config(xml))}


ALIAS_TWO_HOSTS = b"""<alias><name>USERS</name><type>host</type>
  <address>10.0.0.2 10.0.0.3</address></alias>"""

ONLY_ONE_HOST_OUT = b"""<rule><type>pass</type><interface>lan</interface>
  <ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
  <source><address>10.0.0.2</address></source>
  <destination><any></any></destination>
  <descr>only .2 goes out</descr></rule>"""


def test_each_address_in_an_object_is_reported_on_its_own():
    found = findings(build(ALIAS_TWO_HOSTS, ONLY_ONE_HOST_OUT))
    assert "10.0.0.2/32" in found, "the address that really does reach out must be listed"
    assert "10.0.0.3/32" not in found, "the address with no rule must not be listed"


def test_the_finding_names_its_object():
    found = findings(build(ALIAS_TWO_HOSTS, ONLY_ONE_HOST_OUT))
    assert found["10.0.0.2/32"].subject.label == "USERS"


def test_reaching_the_internet_is_reported_with_its_ports():
    found = findings(build(ALIAS_TWO_HOSTS, ONLY_ONE_HOST_OUT))
    entry = found["10.0.0.2/32"]
    assert entry.reaches_internet
    assert entry.internet_ports


def test_an_address_that_breaks_nothing_is_absent():
    assert findings(build()) == {}


WIDE_OPEN_TO_DMZ = b"""<rule><type>pass</type><interface>lan</interface>
  <ipprotocol>inet</ipprotocol>
  <source><address>10.0.0.4</address></source>
  <destination><network>opt1</network></destination>
  <descr>.4 owns the DMZ</descr></rule>"""


LAN_HOST = b"""<alias><name>ADMIN</name><type>host</type>
  <address>10.0.0.4</address></alias>"""


def test_reaching_another_network_on_every_port_names_the_network():
    found = findings(build(LAN_HOST, WIDE_OPEN_TO_DMZ))
    entry = found["10.0.0.4/32"]
    assert entry.reaches_networks_any_port == ["DMZ"]


PUBLISHED = b"""<rule><type>pass</type><interface>wan</interface>
  <ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
  <source><any></any></source>
  <destination><address>10.10.20.50</address><port>8443</port></destination>
  <descr>published</descr></rule>"""

DMZ_HOST = b"""<alias><name>WEB</name><type>host</type>
  <address>10.10.20.50</address></alias>"""


def test_one_open_port_from_the_internet_is_enough_to_report():
    entry = findings(build(DMZ_HOST, PUBLISHED))["10.10.20.50/32"]
    assert entry.reachable_from_internet
    assert "8443" in entry.inbound_internet_ports


INBOUND_ALL_PORTS = b"""<rule><type>pass</type><interface>lan</interface>
  <ipprotocol>inet</ipprotocol>
  <source><network>lan</network></source>
  <destination><address>10.10.20.60</address></destination>
  <descr>LAN owns this host</descr></rule>"""

DMZ_HOST_2 = b"""<alias><name>DB</name><type>host</type>
  <address>10.10.20.60</address></alias>"""


def test_reachable_from_another_network_on_every_port_names_it():
    entry = findings(build(DMZ_HOST_2, INBOUND_ALL_PORTS))["10.10.20.60/32"]
    assert entry.reachable_from_networks_any_port == ["LAN"]


def test_a_single_port_inbound_from_a_network_is_not_wide_open():
    """"Any port" means the whole range. One published port is not that."""
    rule = INBOUND_ALL_PORTS.replace(
        b"<destination><address>10.10.20.60</address></destination>",
        b"<destination><address>10.10.20.60</address><port>5432</port></destination>",
    ).replace(
        b"<ipprotocol>inet</ipprotocol>",
        b"<ipprotocol>inet</ipprotocol><protocol>tcp</protocol>",
    )
    entry = findings(build(DMZ_HOST_2, rule)).get("10.10.20.60/32")
    assert entry is None or entry.reachable_from_networks_any_port == []


OUT_TO_ANYTHING = b"""<rule><type>pass</type><interface>lan</interface>
  <ipprotocol>inet</ipprotocol>
  <source><address>10.0.0.5</address></source>
  <destination><any></any></destination>
  <descr>.5 may do anything</descr></rule>"""

LAN_HOST_2 = b"""<alias><name>OPEN</name><type>host</type>
  <address>10.0.0.5</address></alias>"""


def test_a_host_does_not_reach_its_own_network():
    """Same-segment traffic never reaches the firewall, so it is not a finding."""
    entry = findings(build(LAN_HOST_2, OUT_TO_ANYTHING))["10.0.0.5/32"]
    assert "LAN" not in entry.reaches_networks_any_port
    assert "DMZ" in entry.reaches_networks_any_port, "other networks are still reported"
