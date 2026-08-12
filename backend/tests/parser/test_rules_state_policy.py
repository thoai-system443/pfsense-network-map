"""Fields reported from a real 2.7 backup that the parser did not recognise.

None of the three changes which packets a rule matches, so they are recognised
and ignored rather than warned about: statepolicy and pflow decide how state is
kept and exported, and target_subnet belongs to outbound NAT, which runs after
the filter decision and so cannot change a verdict.
"""

from app.parser.loader import parse_config

HEAD = b"""<?xml version="1.0"?><pfsense><version>22.5</version>
<system><hostname>probe</hostname></system>
<interfaces><lan><if>em1</if><descr>LAN</descr><enable></enable>
<ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan></interfaces>"""


def unrecognised(xml: bytes) -> list[str]:
    return [w.path for w in parse_config(xml).warnings if "unrecognised" in w.message]


def test_state_policy_and_pflow_are_recognised():
    xml = (
        HEAD
        + b"""<filter><rule><type>pass</type><interface>lan</interface>
    <ipprotocol>inet</ipprotocol>
    <source><any></any></source><destination><any></any></destination>
    <statepolicy>if-bound</statepolicy><pflow></pflow>
    <descr>state policy</descr></rule></filter></pfsense>"""
    )
    assert unrecognised(xml) == []


def test_state_policy_does_not_change_the_verdict():
    """It decides how state is keyed, not whether the first packet gets through."""
    from app.engine.evaluate import check

    def build(extra: bytes) -> bytes:
        return (
            HEAD
            + b"""<filter><rule><type>pass</type><interface>lan</interface>
        <ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
        <source><network>lan</network></source>
        <destination><any></any><port>443</port></destination>
        """
            + extra
            + b"""<descr>allow</descr></rule></filter></pfsense>"""
        )

    plain = check(parse_config(build(b"")), "192.168.1.9", "8.8.8.8", 443, "tcp")
    bound = check(
        parse_config(build(b"<statepolicy>if-bound</statepolicy>")),
        "192.168.1.9",
        "8.8.8.8",
        443,
        "tcp",
    )
    assert plain.verdict == bound.verdict == "pass"


def test_outbound_nat_target_subnet_is_recognised():
    xml = (
        HEAD
        + b"""<filter></filter><nat><outbound><mode>hybrid</mode>
    <rule><interface>wan</interface>
      <source><network>192.168.1.0/24</network></source>
      <target></target><target_subnet>24</target_subnet>
      <descr>outbound</descr></rule></outbound></nat></pfsense>"""
    )
    assert unrecognised(xml) == []
