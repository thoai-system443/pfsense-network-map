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


def test_check_reports_verdict_and_deciding_rule():
    config_id = upload("basic.xml")
    body = client.post(
        f"/api/v1/configs/{config_id}/query/check",
        json={"source": "192.168.1.50", "destination": "8.8.8.8", "port": 443, "protocol": "tcp"},
    ).json()
    assert body["verdict"] == "pass"
    assert body["decided_by"]["descr"] == "Allow LAN to any HTTPS"


def test_check_reports_nat_translation():
    config_id = upload("nat_portforward.xml")
    body = client.post(
        f"/api/v1/configs/{config_id}/query/check",
        json={"source": "8.8.8.8", "destination": "203.0.113.2", "port": 443, "protocol": "tcp"},
    ).json()
    assert body["translated_address"] == "192.168.1.10"


def test_from_returns_regions_covering_the_space():
    config_id = upload("basic.xml")
    body = client.post(
        f"/api/v1/configs/{config_id}/query/from",
        json={"source": "192.168.1.50", "protocol": "tcp"},
    ).json()
    assert any(r["verdict"] == "pass" and r["ports"] == "443" for r in body)


def test_to_returns_sources_grouped_by_interface():
    config_id = upload("basic.xml")
    body = client.post(
        f"/api/v1/configs/{config_id}/query/to",
        json={"destination": "8.8.8.8", "port": 443, "protocol": "tcp"},
    ).json()
    assert any(r["in_interface"] == "lan" and r["verdict"] == "pass" for r in body)


def test_source_may_be_an_interface_name():
    config_id = upload("basic.xml")
    body = client.post(
        f"/api/v1/configs/{config_id}/query/from",
        json={"source": "lan", "protocol": "tcp"},
    ).json()
    assert any(r["verdict"] == "pass" for r in body)


def test_source_may_be_an_alias_name():
    config_id = upload("basic.xml")
    body = client.post(
        f"/api/v1/configs/{config_id}/query/from",
        json={"source": "WEB_SERVERS", "protocol": "tcp"},
    ).json()
    assert any(r["verdict"] == "pass" for r in body)


def test_unusable_source_returns_400():
    config_id = upload("basic.xml")
    response = client.post(
        f"/api/v1/configs/{config_id}/query/from",
        json={"source": "not-an-address", "protocol": "tcp"},
    )
    assert response.status_code == 400


def test_check_of_a_subnet_returns_regions_not_one_verdict():
    config_id = upload("basic.xml")
    body = client.post(
        f"/api/v1/configs/{config_id}/query/check",
        json={
            "source": "192.168.1.0/24",
            "destination": "8.8.8.8",
            "port": 443,
            "protocol": "tcp",
        },
    ).json()
    assert body["kind"] == "regions"
    assert body["regions"]
    assert all("sources" in region and "verdict" in region for region in body["regions"])


def test_check_of_one_host_still_returns_a_point_verdict():
    config_id = upload("basic.xml")
    body = client.post(
        f"/api/v1/configs/{config_id}/query/check",
        json={"source": "192.168.1.50", "destination": "8.8.8.8", "port": 443, "protocol": "tcp"},
    ).json()
    assert body["kind"] == "point"
    assert body["verdict"] == "pass"


def test_check_with_protocol_any_reports_each_protocol():
    config_id = upload("basic.xml")
    body = client.post(
        f"/api/v1/configs/{config_id}/query/check",
        json={"source": "192.168.1.50", "destination": "8.8.8.8", "port": 443, "protocol": "any"},
    ).json()
    assert set(body["per_protocol"]) == {"tcp", "udp", "icmp"}
    assert body["verdict"] in {"pass", "block", "partial"}


def test_path_of_a_subnet_returns_regions():
    config_id = upload("routed.xml")
    body = client.post(
        f"/api/v1/configs/{config_id}/query/path",
        json={
            "source": "192.168.1.0/24",
            "destination": "10.10.20.5",
            "port": 443,
            "protocol": "tcp",
        },
    ).json()
    assert body["kind"] == "regions"
    assert body["regions"]


def test_from_tags_the_protocol_when_a_region_is_protocol_specific():
    config_id = upload("basic.xml")
    body = client.post(
        f"/api/v1/configs/{config_id}/query/from",
        json={"source": "192.168.1.50", "protocol": "any"},
    ).json()
    assert all("protocol" in region for region in body)
