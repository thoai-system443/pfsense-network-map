"""Audit probes. Each asserts the CORRECT behaviour, so a failure proves a bug.

Scratch file: delete once the findings are turned into a plan.
"""

from pathlib import Path

from app.engine.evaluate import check, explore_from, explore_to
from app.engine.ipset import IpSet
from app.parser.loader import parse_config

FIXTURES = Path(__file__).parent.parent / "fixtures"


def load(name: str):
    return parse_config((FIXTURES / name).read_bytes())


def build(rules_xml: str, extra: str = "") -> object:
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


class TestSubnetAsInput:
    """A subnet is a set of addresses, not one address."""

    CONFIG = """
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

    def test_one_address_in_the_subnet_is_blocked(self):
        assert check(build(self.CONFIG), "192.168.1.50", "8.8.8.8", 443, "tcp").verdict == "block"

    def test_another_address_in_the_same_subnet_passes(self):
        assert check(build(self.CONFIG), "192.168.1.9", "8.8.8.8", 443, "tcp").verdict == "pass"

    def test_asking_about_the_whole_subnet_must_not_answer_for_one_host(self):
        """The engine has no way to say "some of this subnet, not all of it".

        A caller handing in 192.168.1.0/24 gets whatever the first address says.
        """
        from app.api.v1.query import to_probe_address

        config = build(self.CONFIG)
        probe = to_probe_address(config, "192.168.1.0/24")
        assert probe == "192.168.1.0/24", (
            f"a subnet was silently reduced to the single address {probe}"
        )


class TestProtocolAny:
    CONFIG = """
      <rule><type>pass</type><interface>lan</interface><ipprotocol>inet</ipprotocol>
        <protocol>tcp</protocol>
        <source><network>lan</network></source>
        <destination><any></any><port>443</port></destination>
        <descr>TCP 443 only</descr></rule>
    """

    def test_udp_on_the_same_port_is_blocked(self):
        assert check(build(self.CONFIG), "192.168.1.9", "8.8.8.8", 443, "udp").verdict == "block"

    def test_protocol_any_must_not_report_pass_when_only_tcp_passes(self):
        """"any" currently means "some protocol", but the verdict reads as "all"."""
        result = check(build(self.CONFIG), "192.168.1.9", "8.8.8.8", 443, "any")
        assert result.verdict == "block", (
            "protocol=any reported pass although UDP on this port is denied"
        )


class TestExploreToSources:
    CONFIG = """
      <rule><type>pass</type><interface>wan</interface><ipprotocol>inet</ipprotocol>
        <protocol>tcp</protocol>
        <source><any></any></source>
        <destination><address>10.10.20.50</address><port>8443</port></destination>
        <descr>Published to the internet</descr></rule>
    """

    def test_the_internet_must_appear_as_a_source(self):
        regions = explore_to(build(self.CONFIG), "10.10.20.50", 8443, "tcp")
        passing = [r for r in regions if r.verdict == "pass"]
        outside = IpSet.from_cidr("8.8.8.8/32")
        assert any(
            any(not IpSet.from_cidr(c).intersect(outside).is_empty() for c in r.addresses)
            for r in passing
        ), "explore_to never reports internet sources; it only walks interface subnets"


class TestNatInExplore:
    def test_explore_from_must_apply_the_same_nat_as_check(self):
        config = load("nat_portforward.xml")
        assert check(config, "8.8.8.8", "203.0.113.2", 443, "tcp").verdict == "pass"

        regions = explore_from(config, "8.8.8.8", "tcp")
        public = IpSet.from_cidr("203.0.113.2/32")
        reaches_public = any(
            r.verdict == "pass"
            and any(not IpSet.from_cidr(c).intersect(public).is_empty() for c in r.addresses)
            for r in regions
        )
        assert reaches_public, (
            "check() says the published address is reachable but explore_from does not, "
            "because explore_from skips NAT"
        )


class TestFamily:
    def test_an_ipv6_query_is_answered_rather_than_silently_treated_as_ipv4(self):
        from app.engine import fabric

        config = load("routed.xml")
        firewalls = [fabric.Firewall(id="fw-0", name="fw", config=config)]
        result = fabric.path_check(firewalls, "2001:db8::1", "2001:db8::2", 443, "tcp")
        assert "IPv6" in (result.stopped_reason or ""), (
            f"IPv6 not handled and not reported; got {result.stopped_reason!r}"
        )


class TestNatAcrossFirewalls:
    """A port forward on the first firewall changes where the packet is going."""

    EDGE = b"""<?xml version="1.0"?>
<pfsense><version>22.5</version><system><hostname>fw-edge</hostname></system>
<interfaces>
  <wan><if>em0</if><descr>WAN</descr><enable></enable>
    <ipaddr>203.0.113.2</ipaddr><subnet>30</subnet><gateway>WAN_GW</gateway></wan>
  <opt1><if>em2</if><descr>TRANSIT</descr><enable></enable>
    <ipaddr>10.10.20.1</ipaddr><subnet>24</subnet></opt1>
</interfaces>
<gateways>
  <gateway_item><interface>wan</interface><gateway>203.0.113.1</gateway>
    <name>WAN_GW</name><ipprotocol>inet</ipprotocol><defaultgw></defaultgw></gateway_item>
  <gateway_item><interface>opt1</interface><gateway>10.10.20.2</gateway>
    <name>CORE</name><ipprotocol>inet</ipprotocol></gateway_item>
</gateways>
<staticroutes>
  <route><network>10.20.5.0/24</network><gateway>CORE</gateway><descr>servers</descr></route>
</staticroutes>
<nat><rule>
  <interface>wan</interface><protocol>tcp</protocol>
  <target>10.20.5.10</target><local-port>8443</local-port>
  <source><any></any></source>
  <destination><network>wanip</network><port>443</port></destination>
  <descr>Publish the server behind fw-core</descr>
</rule></nat>
<filter><rule>
  <type>pass</type><interface>wan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
  <source><any></any></source>
  <destination><address>10.20.5.10</address><port>8443</port></destination>
  <descr>Allow the published server</descr>
</rule></filter></pfsense>"""

    CORE = b"""<?xml version="1.0"?>
<pfsense><version>22.5</version><system><hostname>fw-core</hostname></system>
<interfaces>
  <wan><if>em0</if><descr>TRANSIT</descr><enable></enable>
    <ipaddr>10.10.20.2</ipaddr><subnet>24</subnet></wan>
  <lan><if>em1</if><descr>SERVERS</descr><enable></enable>
    <ipaddr>10.20.5.1</ipaddr><subnet>24</subnet></lan>
</interfaces>
<filter><rule>
  <type>block</type><interface>wan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
  <source><any></any></source>
  <destination><network>lan</network><port>8443</port></destination>
  <descr>fw-core refuses 8443</descr>
</rule></filter></pfsense>"""

    def test_the_chain_must_follow_the_translated_destination(self):
        from app.engine import fabric

        firewalls = [
            fabric.Firewall(id="fw-0", name="fw-edge", config=parse_config(self.EDGE)),
            fabric.Firewall(id="fw-1", name="fw-core", config=parse_config(self.CORE)),
        ]
        result = fabric.path_check(firewalls, "8.8.8.8", "203.0.113.2", 443, "tcp")
        names = [hop.firewall_name for hop in result.hops]
        assert names == ["fw-edge", "fw-core"], (
            f"chain stopped at {names}: routing followed the public address instead of the "
            f"NAT target, so fw-core was never consulted"
        )
        assert result.verdict == "block", "fw-core denies 8443, so the path must be blocked"
