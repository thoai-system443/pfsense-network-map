from pathlib import Path

from app.parser.loader import parse_config

FIXTURES = Path(__file__).parent.parent / "fixtures"


def load(name: str):
    return parse_config((FIXTURES / name).read_bytes())


def test_keeps_document_order_in_seq():
    assert [r.seq for r in load("floating.xml").rules] == [0, 1, 2, 3]


def test_floating_rule_defaults_to_not_quick():
    rule = load("floating.xml").rules[0]
    assert (rule.floating, rule.quick, rule.direction) == (True, False, "any")


def test_floating_rule_with_quick_flag_is_quick():
    assert load("floating.xml").rules[1].quick is True


def test_interface_rule_is_quick_and_inbound():
    rule = load("floating.xml").rules[2]
    assert (rule.floating, rule.quick, rule.direction) == (False, True, "in")


def test_multiple_interfaces_are_split_on_comma():
    xml = b"""<?xml version="1.0"?>
<pfsense><version>22.5</version><filter><rule>
<floating>yes</floating><type>block</type><interface>lan,opt1</interface>
<ipprotocol>inet</ipprotocol><protocol>any</protocol>
<source><any></any></source><destination><any></any></destination>
<descr>multi</descr></rule></filter></pfsense>"""
    assert parse_config(xml).rules[0].interfaces == ["lan", "opt1"]


def test_reads_not_flag_on_destination():
    dest = load("not_flag.xml").rules[0].destination
    assert (dest.not_, dest.network) == (True, "opt1")


def test_reads_disabled_flag():
    assert load("disabled.xml").rules[0].disabled is True
    assert load("disabled.xml").rules[1].disabled is False


def test_reads_any_source_and_port_destination():
    rule = load("floating.xml").rules[0]
    assert rule.source.any is True
    assert rule.destination.port == "445"


def test_reject_action_is_preserved():
    xml = b"""<?xml version="1.0"?>
<pfsense><version>22.5</version><filter><rule>
<type>reject</type><interface>lan</interface><ipprotocol>inet</ipprotocol>
<protocol>tcp</protocol><source><any></any></source>
<destination><any></any></destination><descr>r</descr></rule></filter></pfsense>"""
    assert parse_config(xml).rules[0].action == "reject"
