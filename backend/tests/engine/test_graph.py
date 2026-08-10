from pathlib import Path

from app.engine import graph
from app.parser.loader import parse_config

FIXTURES = Path(__file__).parent.parent / "fixtures"


def load(name: str):
    return parse_config((FIXTURES / name).read_bytes())


def test_topology_has_a_firewall_node():
    nodes = graph.topology(load("basic.xml"))["nodes"]
    assert any(n["kind"] == "firewall" for n in nodes)


def test_topology_uses_display_names_not_technical_names():
    nodes = graph.topology(load("vlan_vpn.xml"))["nodes"]
    labels = [n["label"] for n in nodes]
    assert "DMZ" in labels
    assert "opt1" not in labels


def test_topology_marks_vlan_interfaces():
    nodes = graph.topology(load("vlan_vpn.xml"))["nodes"]
    dmz = next(n for n in nodes if n["label"] == "DMZ")
    assert dmz["kind"] == "vlan"


def test_topology_omits_disabled_interfaces():
    labels = [n["label"] for n in graph.topology(load("vlan_vpn.xml"))["nodes"]]
    assert "GUEST" not in labels


def test_topology_includes_vpn_tunnels():
    nodes = graph.topology(load("vlan_vpn.xml"))["nodes"]
    assert any(n["kind"] == "tunnel" for n in nodes)


def test_topology_links_every_interface_to_the_firewall():
    result = graph.topology(load("basic.xml"))
    firewall = next(n["id"] for n in result["nodes"] if n["kind"] == "firewall")
    assert all(e["source"] == firewall for e in result["edges"])


def test_access_graph_has_an_internet_node():
    nodes = graph.access_graph(load("basic.xml"))["nodes"]
    assert any(n["kind"] == "internet" for n in nodes)


def test_access_graph_draws_allowed_flow_from_lan_to_internet():
    edges = graph.access_graph(load("basic.xml"), "tcp")["edges"]
    edge = next(e for e in edges if e["source"] == "lan" and e["target"] == "internet")
    assert "443" in edge["ports"]


def test_access_graph_omits_pairs_with_no_allowed_traffic():
    edges = graph.access_graph(load("disabled.xml"), "tcp")["edges"]
    assert edges == []


def test_access_graph_includes_vpn_tunnels_as_zones():
    nodes = graph.access_graph(load("vlan_vpn.xml"))["nodes"]
    assert any(n["kind"] == "tunnel" and n["label"] == "Remote access" for n in nodes)


def test_access_graph_draws_the_vpn_to_lan_flow():
    edges = graph.access_graph(load("vlan_vpn.xml"))["edges"]
    edge = next(e for e in edges if e["target"] == "lan" and e["source"].startswith("tunnel-"))
    assert edge["rules"][0]["descr"] == "VPN to LAN"


def test_access_edge_carries_the_rules_that_created_it():
    edges = graph.access_graph(load("basic.xml"), "tcp")["edges"]
    edge = next(e for e in edges if e["target"] == "internet")
    assert edge["rules"][0]["descr"] == "Allow LAN to any HTTPS"
