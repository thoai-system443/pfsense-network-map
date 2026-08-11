"""Routing was deliberately out of scope for a single firewall.

With more than one firewall it stops being optional: answering "can A reach B"
means knowing which firewalls the packet crosses, and that is exactly what the
routing table says.
"""

from pathlib import Path

from app.engine import routing
from app.parser.loader import parse_config

FIXTURES = Path(__file__).parent.parent / "fixtures"


def load(name: str):
    return parse_config((FIXTURES / name).read_bytes())


def table(name: str):
    return routing.build_table(load(name))


class TestParsing:
    def test_reads_gateways_with_their_interface(self):
        gateways = load("routed.xml").gateways
        core = next(g for g in gateways if g.name == "CORE_ROUTER")
        assert (core.interface, core.address) == ("opt1", "10.10.20.2")

    def test_marks_the_default_gateway(self):
        gateways = load("routed.xml").gateways
        assert [g.name for g in gateways if g.default] == ["WAN_GW"]

    def test_reads_static_routes(self):
        routes = load("routed.xml").static_routes
        assert ("10.20.0.0/16", "CORE_ROUTER") in [(r.network, r.gateway) for r in routes]

    def test_a_config_without_routing_sections_is_fine(self):
        config = load("basic.xml")
        assert config.gateways == []
        assert config.static_routes == []


class TestLookup:
    def test_a_directly_connected_subnet_has_no_next_hop(self):
        entry = routing.lookup(table("routed.xml"), "192.168.1.50")
        assert entry.out_interface == "lan"
        assert entry.next_hop is None
        assert entry.kind == "connected"

    def test_a_static_route_resolves_to_its_gateway(self):
        entry = routing.lookup(table("routed.xml"), "10.20.9.9")
        assert entry.out_interface == "opt1"
        assert entry.next_hop == "10.10.20.2"
        assert entry.kind == "static"

    def test_the_longest_prefix_wins(self):
        entry = routing.lookup(table("routed.xml"), "10.20.5.5")
        assert entry.network == "10.20.5.0/24"

    def test_anything_else_takes_the_default_route(self):
        entry = routing.lookup(table("routed.xml"), "8.8.8.8")
        assert entry.out_interface == "wan"
        assert entry.next_hop == "203.0.113.1"
        assert entry.kind == "default"

    def test_connected_beats_the_default_route(self):
        entry = routing.lookup(table("routed.xml"), "203.0.113.1")
        assert entry.kind == "connected"

    def test_no_default_route_means_no_answer(self):
        assert routing.lookup(table("basic.xml"), "8.8.8.8") is None

    def test_a_static_route_to_an_unknown_gateway_is_dropped(self):
        config = load("routed.xml")
        config.static_routes[0].gateway = "GHOST"
        entries = routing.build_table(config)
        assert not any(e.network == "10.20.0.0/16" for e in entries)
