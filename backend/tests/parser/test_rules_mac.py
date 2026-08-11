"""Fields found in a real pfSense backup that the initial schema guess missed.

srcmac, dstmac and bridgeto narrow a rule in ways the engine does not model, so
recognising them is not enough: rules that use them have to say so, or the tool
will report more access than the firewall actually grants.
"""

from pathlib import Path

from app.parser.loader import parse_config

FIXTURES = Path(__file__).parent.parent / "fixtures"


def load(name: str):
    return parse_config((FIXTURES / name).read_bytes())


def test_mac_and_bridge_fields_are_recognised():
    unknown = [w for w in load("mac_and_bridge.xml").warnings if "unrecognised" in w.message]
    assert unknown == []


def test_source_mac_rule_is_flagged_as_not_modelled():
    warnings = load("mac_and_bridge.xml").warnings
    assert any("srcmac" in w.message and "rule[0]" in w.path for w in warnings)


def test_destination_mac_rule_is_flagged_as_not_modelled():
    warnings = load("mac_and_bridge.xml").warnings
    assert any("dstmac" in w.message and "rule[1]" in w.path for w in warnings)


def test_bridged_rule_is_flagged_as_not_modelled():
    warnings = load("mac_and_bridge.xml").warnings
    assert any("bridgeto" in w.message and "rule[2]" in w.path for w in warnings)


def test_the_flag_says_results_may_overstate_access():
    warnings = load("mac_and_bridge.xml").warnings
    mac_warning = next(w for w in warnings if "srcmac" in w.message)
    assert "more access" in mac_warning.message


def test_a_rule_without_those_fields_is_not_flagged():
    warnings = load("mac_and_bridge.xml").warnings
    assert not any("rule[3]" in w.path for w in warnings)


def test_the_rule_itself_still_parses_normally():
    rules = load("mac_and_bridge.xml").rules
    assert rules[0].descr == "Allow one laptop to HTTPS"
    assert rules[0].destination.port == "443"
    assert len(rules) == 4
