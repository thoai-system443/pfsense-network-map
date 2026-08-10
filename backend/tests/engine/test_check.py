from pathlib import Path

from app.engine.evaluate import check
from app.parser.loader import parse_config

FIXTURES = Path(__file__).parent.parent / "fixtures"


def load(name: str):
    return parse_config((FIXTURES / name).read_bytes())


def test_matching_pass_rule_allows():
    result = check(load("basic.xml"), "192.168.1.50", "8.8.8.8", 443, "tcp")
    assert result.verdict == "pass"
    assert result.decided_by.descr == "Allow LAN to any HTTPS"


def test_matching_block_rule_denies():
    result = check(load("basic.xml"), "192.168.1.50", "8.8.8.8", 23, "tcp")
    assert result.verdict == "block"
    assert result.decided_by.descr == "Block telnet"


def test_no_matching_rule_falls_through_to_default_deny():
    result = check(load("basic.xml"), "192.168.1.50", "8.8.8.8", 9999, "tcp")
    assert result.verdict == "block"
    assert result.decided_by is None


def test_inbound_interface_is_reported():
    assert check(load("basic.xml"), "192.168.1.50", "8.8.8.8", 443, "tcp").in_interface == "lan"


def test_non_quick_floating_rule_is_overridden_by_interface_rule():
    """The single most important behaviour in this engine."""
    result = check(load("floating.xml"), "192.168.1.50", "10.10.20.5", 445, "tcp")
    assert result.verdict == "pass"
    assert result.decided_by.descr == "Allow LAN to DMZ SMB"


def test_quick_floating_rule_wins_over_later_interface_rule():
    result = check(load("floating.xml"), "192.168.1.50", "10.10.20.5", 23, "tcp")
    assert result.verdict == "block"
    assert result.decided_by.descr == "Hard block telnet, quick"


def test_disabled_rule_does_not_decide():
    result = check(load("disabled.xml"), "192.168.1.50", "8.8.8.8", 22, "tcp")
    assert result.verdict == "block"
    assert result.decided_by.descr == "Block SSH"


def test_not_flag_excludes_the_named_network():
    config = load("not_flag.xml")
    assert check(config, "192.168.1.50", "10.10.20.5", 80, "tcp").verdict == "block"
    assert check(config, "192.168.1.50", "8.8.8.8", 80, "tcp").verdict == "pass"


def test_port_forward_is_applied_before_the_filter():
    result = check(load("nat_portforward.xml"), "8.8.8.8", "203.0.113.2", 443, "tcp")
    assert result.verdict == "pass"
    assert (result.translated_address, result.translated_port) == ("192.168.1.10", 8443)


def test_public_address_without_translation_is_blocked():
    config = load("nat_portforward.xml")
    config.nat.port_forwards[0].disabled = True
    assert check(config, "8.8.8.8", "203.0.113.2", 443, "tcp").verdict == "block"


def test_unresolvable_alias_marks_result_unresolved():
    result = check(load("unresolvable_alias.xml"), "192.168.1.50", "8.8.8.8", 80, "tcp")
    assert result.unresolved is True


def test_trace_lists_every_rule_that_was_examined():
    result = check(load("floating.xml"), "192.168.1.50", "10.10.20.5", 445, "tcp")
    assert [entry.rule.descr for entry in result.trace][0] == "Soft block SMB, not quick"


def test_source_in_openvpn_tunnel_is_evaluated_against_openvpn_rules():
    """Tunnel traffic must not fall through to the WAN ruleset."""
    result = check(load("vlan_vpn.xml"), "10.8.0.5", "192.168.1.10", 445, "tcp")
    assert result.in_interface == "openvpn"
    assert result.verdict == "pass"
    assert result.decided_by.descr == "VPN to LAN"


def test_source_in_ipsec_remote_network_uses_the_ipsec_pseudo_interface():
    result = check(load("vlan_vpn.xml"), "10.20.0.5", "192.168.1.10", 445, "tcp")
    assert result.in_interface == "enc0"
    assert result.verdict == "block"


def test_source_outside_every_known_network_falls_back_to_wan():
    result = check(load("vlan_vpn.xml"), "8.8.8.8", "192.168.1.10", 445, "tcp")
    assert result.in_interface == "wan"
