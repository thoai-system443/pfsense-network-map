from pathlib import Path

from app.engine import nat
from app.engine.resolver import Resolver
from app.parser.loader import parse_config

FIXTURES = Path(__file__).parent.parent / "fixtures"


def setup(name: str):
    config = parse_config((FIXTURES / name).read_bytes())
    return config, Resolver(config)


def test_port_forward_rewrites_address_and_port():
    config, resolver = setup("nat_portforward.xml")
    result = nat.translate_destination(config, resolver, "wan", "203.0.113.2", 443, "tcp")
    assert (result.address, result.port) == ("192.168.1.10", 8443)


def test_translation_records_which_rule_did_it():
    config, resolver = setup("nat_portforward.xml")
    result = nat.translate_destination(config, resolver, "wan", "203.0.113.2", 443, "tcp")
    assert "Publish web server" in result.via


def test_non_matching_port_is_not_translated():
    config, resolver = setup("nat_portforward.xml")
    assert nat.translate_destination(config, resolver, "wan", "203.0.113.2", 8080, "tcp") is None


def test_wrong_interface_is_not_translated():
    config, resolver = setup("nat_portforward.xml")
    assert nat.translate_destination(config, resolver, "lan", "203.0.113.2", 443, "tcp") is None


def test_wrong_protocol_is_not_translated():
    config, resolver = setup("nat_portforward.xml")
    assert nat.translate_destination(config, resolver, "wan", "203.0.113.2", 443, "udp") is None


def test_one_to_one_maps_external_to_internal():
    config, resolver = setup("nat_portforward.xml")
    result = nat.translate_destination(config, resolver, "wan", "203.0.113.3", 22, "tcp")
    assert (result.address, result.port) == ("192.168.1.50", 22)


def test_disabled_port_forward_is_ignored():
    config, resolver = setup("nat_portforward.xml")
    config.nat.port_forwards[0].disabled = True
    assert nat.translate_destination(config, resolver, "wan", "203.0.113.2", 443, "tcp") is None
