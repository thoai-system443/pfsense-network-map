from pathlib import Path

from app.engine import ruleset
from app.parser.loader import parse_config

FIXTURES = Path(__file__).parent.parent / "fixtures"


def load(name: str):
    return parse_config((FIXTURES / name).read_bytes())


def test_source_in_lan_subnet_picks_lan():
    assert ruleset.inbound_interface(load("basic.xml"), "192.168.1.50") == "lan"


def test_unknown_source_falls_back_to_wan():
    assert ruleset.inbound_interface(load("basic.xml"), "8.8.8.8") == "wan"


def test_longest_prefix_wins_when_subnets_overlap():
    config = load("basic.xml")
    config.interfaces[1].subnet = 16
    config.interfaces.append(
        config.interfaces[1].model_copy(
            update={
                "name": "opt9",
                "descr": "NARROW",
                "ipaddr": "192.168.1.1",
                "subnet": 24,
            }
        )
    )
    assert ruleset.inbound_interface(config, "192.168.1.50") == "opt9"


def test_floating_rules_come_before_interface_rules():
    order = [r.descr for r in ruleset.build(load("floating.xml"), "lan")]
    assert order.index("Soft block SMB, not quick") < order.index("Allow LAN to DMZ SMB")


def test_disabled_rules_are_dropped():
    descriptions = [r.descr for r in ruleset.build(load("disabled.xml"), "lan")]
    assert "Disabled SSH allow" not in descriptions


def test_rules_for_other_interfaces_are_excluded():
    descriptions = [r.descr for r in ruleset.build(load("floating.xml"), "opt1")]
    assert "Allow LAN to DMZ SMB" not in descriptions


def test_floating_rule_applies_to_every_listed_interface():
    descriptions = [r.descr for r in ruleset.build(load("floating.xml"), "lan")]
    assert "Hard block telnet, quick" in descriptions


def test_anti_lockout_rule_is_added_on_lan():
    added = [r for r in ruleset.build(load("basic.xml"), "lan") if r.synthetic]
    assert len(added) == 1
    assert added[0].action == "pass"


def test_anti_lockout_rule_is_not_added_on_wan():
    assert [r for r in ruleset.build(load("basic.xml"), "wan") if r.synthetic] == []
