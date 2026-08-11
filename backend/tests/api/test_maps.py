from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

FIXTURES = Path(__file__).parent.parent / "fixtures"
client = TestClient(app)


def upload(name: str) -> str:
    with (FIXTURES / name).open("rb") as handle:
        return client.post("/api/v1/configs", files={"file": (name, handle, "text/xml")}).json()[
            "config_id"
        ]


def test_topology_returns_nodes_and_edges():
    body = client.get(f"/api/v1/configs/{upload('vlan_vpn.xml')}/topology").json()
    assert {n["kind"] for n in body["nodes"]} >= {"firewall", "interface", "vlan", "tunnel"}
    assert body["edges"]
    # A single firewall shares nothing.
    assert not any(n["shared"] for n in body["nodes"])


def test_access_graph_returns_edges_with_ports():
    body = client.get(f"/api/v1/configs/{upload('basic.xml')}/access-graph?protocol=tcp").json()
    edge = next(e for e in body["edges"] if e["target"] == "net:internet")
    assert "443" in edge["ports"]


def test_unknown_config_returns_404():
    assert client.get("/api/v1/configs/nope/topology").status_code == 404
