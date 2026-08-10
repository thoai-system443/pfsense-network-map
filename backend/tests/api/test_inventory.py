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


def test_lists_interfaces_with_display_names():
    config_id = upload("vlan_vpn.xml")
    body = client.get(f"/api/v1/configs/{config_id}/interfaces").json()
    assert {i["descr"] for i in body} >= {"WAN", "LAN", "DMZ"}


def test_lists_aliases_without_resolution_by_default():
    config_id = upload("alias_nested.xml")
    body = client.get(f"/api/v1/configs/{config_id}/aliases").json()
    assert next(a for a in body if a["name"] == "TIER_TWO")["items"] == [
        "DB_HOSTS",
        "APP_HOSTS",
    ]


def test_resolved_query_expands_nested_aliases():
    config_id = upload("alias_nested.xml")
    body = client.get(f"/api/v1/configs/{config_id}/aliases?resolved=true").json()
    entry = next(a for a in body if a["name"] == "ALL_SERVERS")
    assert entry["resolved_addresses"] == [
        "192.168.1.20/31",
        "192.168.1.30/32",
        "192.168.1.40/32",
    ]


def test_alias_cycle_is_reported_not_crashed():
    config_id = upload("alias_nested.xml")
    body = client.get(f"/api/v1/configs/{config_id}/aliases?resolved=true").json()
    entry = next(a for a in body if a["name"] == "LOOP_A")
    assert "cycle" in entry["error"]


def test_lists_rules_in_evaluation_order_for_an_interface():
    config_id = upload("floating.xml")
    body = client.get(f"/api/v1/configs/{config_id}/rules?interface=lan").json()
    assert body[0]["descr"] == "Soft block SMB, not quick"


def test_lists_nat_entries():
    config_id = upload("nat_portforward.xml")
    body = client.get(f"/api/v1/configs/{config_id}/nat").json()
    assert body["port_forwards"][0]["target"] == "192.168.1.10"
