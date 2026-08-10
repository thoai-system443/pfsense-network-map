from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app

FIXTURES = Path(__file__).parent.parent / "fixtures"
client = TestClient(app)


def upload(name: str = "basic.xml"):
    with (FIXTURES / name).open("rb") as handle:
        return client.post("/api/v1/configs", files={"file": (name, handle, "text/xml")})


def test_upload_returns_an_id_and_summary():
    body = upload().json()
    assert body["version"] == "22.5"
    assert body["counts"]["interfaces"] == 2
    assert body["counts"]["rules"] == 2
    assert body["config_id"]


def test_upload_reports_parse_warnings():
    body = upload("unresolvable_alias.xml").json()
    assert any("offline" in w["message"] for w in body["warnings"])


def test_uploaded_config_can_be_fetched_again():
    config_id = upload().json()["config_id"]
    assert client.get(f"/api/v1/configs/{config_id}").json()["version"] == "22.5"


def test_unknown_id_returns_404():
    assert client.get("/api/v1/configs/does-not-exist").status_code == 404


def test_delete_removes_the_config():
    config_id = upload().json()["config_id"]
    assert client.delete(f"/api/v1/configs/{config_id}").status_code == 204
    assert client.get(f"/api/v1/configs/{config_id}").status_code == 404


def test_malformed_xml_returns_400():
    response = client.post(
        "/api/v1/configs", files={"file": ("bad.xml", b"<pfsense><oops>", "text/xml")}
    )
    assert response.status_code == 400
    assert "not valid XML" in response.json()["detail"]


def test_oversized_upload_returns_413():
    from app.settings import settings

    payload = b"x" * (settings.max_upload_bytes + 1)
    response = client.post("/api/v1/configs", files={"file": ("big.xml", payload, "text/xml")})
    assert response.status_code == 413


def test_store_evicts_least_recently_used_beyond_the_limit():
    from app.parser.types import ParsedConfig
    from app.store import ConfigStore

    small = ConfigStore(max_items=2)
    first = small.put(ParsedConfig(), "a.xml")
    second = small.put(ParsedConfig(), "b.xml")
    small.get(first)
    small.put(ParsedConfig(), "c.xml")

    assert small.get(first) is not None
    with pytest.raises(KeyError):
        small.get(second)
