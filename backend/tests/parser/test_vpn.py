from pathlib import Path

from app.parser.loader import parse_config

FIXTURES = Path(__file__).parent.parent / "fixtures"


def load(name: str):
    return parse_config((FIXTURES / name).read_bytes())


def test_reads_openvpn_server_tunnel():
    tunnel = load("vlan_vpn.xml").vpn.tunnels[0]
    assert tunnel.kind == "openvpn-server"
    assert tunnel.tunnel_network == "10.8.0.0/24"
    assert tunnel.interface_name == "openvpn"


def test_reads_ipsec_phase2_networks():
    tunnel = next(t for t in load("vlan_vpn.xml").vpn.tunnels if t.kind == "ipsec-p2")
    assert tunnel.remote_networks == ["10.20.0.0/24"]
    assert tunnel.interface_name == "enc0"


def test_config_without_vpn_gives_no_tunnels():
    assert load("basic.xml").vpn.tunnels == []
