from pathlib import Path

from app.parser.loader import parse_config

FIXTURES = Path(__file__).parent.parent / "fixtures"


def load(name: str):
    return parse_config((FIXTURES / name).read_bytes())


def test_reads_port_forward_target_and_local_port():
    pf = load("nat_portforward.xml").nat.port_forwards[0]
    assert (pf.interface, pf.target, pf.local_port) == ("wan", "192.168.1.10", "8443")


def test_port_forward_keeps_original_destination():
    pf = load("nat_portforward.xml").nat.port_forwards[0]
    assert (pf.destination.network, pf.destination.port) == ("wanip", "443")


def test_reads_one_to_one_mapping():
    mapping = load("nat_portforward.xml").nat.one_to_one[0]
    assert (mapping.external, mapping.internal) == ("203.0.113.3", "192.168.1.50")


def test_reads_outbound_rule():
    rule = load("nat_portforward.xml").nat.outbound[0]
    assert (rule.interface, rule.source) == ("wan", "192.168.1.0/24")


def test_config_without_nat_section_gives_empty_lists():
    nat = load("basic.xml").nat
    assert (nat.port_forwards, nat.one_to_one, nat.outbound) == ([], [], [])
