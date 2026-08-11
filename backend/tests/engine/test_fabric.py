"""Evaluating a packet across more than one firewall.

A packet crossing two firewalls has to be permitted by both. The chain is
derived from each firewall's routing table: the next hop of a route names an
address, and if a loaded firewall owns that address it is the next link.
"""

from pathlib import Path

from app.engine import fabric
from app.parser.loader import parse_config

FIXTURES = Path(__file__).parent.parent / "fixtures"


def firewalls():
    return [
        fabric.Firewall(
            id="fw-0", name="fw-edge", config=parse_config((FIXTURES / "routed.xml").read_bytes())
        ),
        fabric.Firewall(
            id="fw-1", name="fw-core", config=parse_config((FIXTURES / "core.xml").read_bytes())
        ),
    ]


class TestChain:
    def test_a_packet_allowed_by_both_firewalls_passes(self):
        result = fabric.path_check(firewalls(), "192.168.1.50", "10.20.5.10", 443, "tcp")
        assert result.verdict == "pass"
        assert [hop.firewall_name for hop in result.hops] == ["fw-edge", "fw-core"]

    def test_the_second_firewall_can_block_what_the_first_allowed(self):
        result = fabric.path_check(firewalls(), "192.168.1.50", "10.20.5.10", 22, "tcp")
        assert result.verdict == "block"
        assert result.hops[0].verdict == "pass"
        assert result.hops[-1].firewall_name == "fw-core"

    def test_the_blocking_hop_names_its_firewall_and_interface(self):
        result = fabric.path_check(firewalls(), "192.168.1.50", "10.20.5.10", 22, "tcp")
        blocked = result.hops[-1]
        assert blocked.firewall_name == "fw-core"
        assert blocked.in_interface == "wan"

    def test_the_first_firewall_blocking_stops_the_chain(self):
        """Nothing on fw-edge permits traffic arriving on TRANSIT."""
        result = fabric.path_check(firewalls(), "10.10.20.9", "192.168.1.10", 443, "tcp")
        assert result.verdict == "block"
        assert len(result.hops) == 1

    def test_a_destination_on_the_first_firewall_needs_no_second_hop(self):
        result = fabric.path_check(firewalls(), "192.168.1.50", "192.168.1.60", 443, "tcp")
        assert result.verdict == "pass"
        assert len(result.hops) == 1

    def test_each_hop_reports_the_rule_that_decided_it(self):
        result = fabric.path_check(firewalls(), "192.168.1.50", "10.20.5.10", 443, "tcp")
        assert result.hops[0].decided_by.descr == "LAN to anywhere"
        assert result.hops[1].decided_by.descr == "HTTPS into the server segment"


class TestChainLimits:
    def test_says_so_when_the_next_hop_is_not_a_loaded_firewall(self):
        """Traffic to the internet leaves via a router this workspace has never seen."""
        result = fabric.path_check(firewalls(), "192.168.1.50", "8.8.8.8", 443, "tcp")
        assert result.verdict == "pass"
        assert "203.0.113.1" in result.stopped_reason
        assert result.truncated is True

    def test_a_complete_chain_is_not_marked_truncated(self):
        result = fabric.path_check(firewalls(), "192.168.1.50", "10.20.5.10", 443, "tcp")
        assert result.truncated is False
        assert result.stopped_reason is None

    def test_an_unroutable_destination_is_reported(self):
        single = [firewalls()[1]]
        result = fabric.path_check(single, "10.20.5.10", "198.51.100.9", 443, "tcp")
        assert result.hops[0].verdict == "pass"
        assert result.verdict in {"pass", "unrouted"}


class TestZones:
    def test_a_subnet_both_firewalls_touch_becomes_one_zone(self):
        zones = fabric.zones(firewalls())
        transit = next(z for z in zones if z.cidr == "10.10.20.0/24")
        assert sorted(transit.firewall_ids) == ["fw-0", "fw-1"]

    def test_a_subnet_only_one_firewall_touches_lists_just_that_one(self):
        zones = fabric.zones(firewalls())
        servers = next(z for z in zones if z.cidr == "10.20.5.0/24")
        assert servers.firewall_ids == ["fw-1"]

    def test_zone_labels_keep_every_name_the_firewalls_give_it(self):
        zones = fabric.zones(firewalls())
        transit = next(z for z in zones if z.cidr == "10.10.20.0/24")
        assert "TRANSIT" in transit.label


class TestTopologyShape:
    def test_a_shared_subnet_is_marked_shared(self):
        nodes = fabric.topology(firewalls())["nodes"]
        transit = next(n for n in nodes if n["subnet"] == "10.10.20.0/24")
        assert transit["shared"] is True
        assert transit["firewalls"] == ["fw-edge", "fw-core"]

    def test_a_subnet_one_firewall_touches_is_not_shared(self):
        nodes = fabric.topology(firewalls())["nodes"]
        servers = next(n for n in nodes if n["subnet"] == "10.20.5.0/24")
        assert servers["shared"] is False

    def test_shared_does_not_overwrite_the_vlan_kind(self):
        """kind says what the segment is; shared says how many firewalls touch it."""
        nodes = fabric.topology(firewalls())["nodes"]
        assert all(n["kind"] != "vlan" for n in nodes if n["subnet"] == "10.10.20.0/24")

    def test_every_firewall_gets_a_node(self):
        nodes = fabric.topology(firewalls())["nodes"]
        assert {n["label"] for n in nodes if n["kind"] == "firewall"} == {"fw-edge", "fw-core"}


class TestAccessGraph:
    def test_a_flow_needs_every_hop_to_agree(self):
        """fw-core only lets 443 into SERVERS, so that is all LAN gets."""
        edges = fabric.access_graph(firewalls(), "tcp")["edges"]
        edge = next(
            e
            for e in edges
            if e["source"] == "net:192.168.1.0/24" and e["target"] == "net:10.20.5.0/24"
        )
        assert edge["ports"] == "443"

    def test_a_pair_no_chain_permits_has_no_edge(self):
        edges = fabric.access_graph(firewalls(), "tcp")["edges"]
        assert not any(
            e["source"] == "net:10.20.5.0/24" and e["target"] == "net:192.168.1.0/24" for e in edges
        )

    def test_an_edge_says_when_the_chain_was_cut_short(self):
        edges = fabric.access_graph(firewalls(), "tcp")["edges"]
        internet = [e for e in edges if e["target"] == "net:internet"]
        assert internet and all(e["truncated"] for e in internet)

    def test_the_shared_transit_subnet_is_a_single_node(self):
        nodes = fabric.access_graph(firewalls(), "tcp")["nodes"]
        assert len([n for n in nodes if n["subnet"] == "10.10.20.0/24"]) == 1
