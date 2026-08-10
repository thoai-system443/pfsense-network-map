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
