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


def test_report_lists_exposures_per_subject():
    body = client.get(f"/api/v1/configs/{upload('risky.xml')}/risk").json()
    lan = next(e for e in body["exposures"] if e["subject"]["id"] == "lan")
    assert lan["reaches_internet"] is True
    assert "DMZ" in lan["reaches_other_subnets_any_port"]


def test_report_lists_deny_all_findings():
    body = client.get(f"/api/v1/configs/{upload('risky.xml')}/risk").json()
    kinds = {f["kind"] for f in body["deny_all"]}
    assert {"block-all-not-quick", "unreachable-rule"} <= kinds


def test_port_search_lists_sources():
    config_id = upload("risky.xml")
    body = client.get(f"/api/v1/configs/{config_id}/risk/port?port=5432&protocol=tcp").json()
    assert "DMZ" in {r["source_label"] for r in body}


def test_port_search_rejects_a_port_out_of_range():
    config_id = upload("risky.xml")
    assert client.get(f"/api/v1/configs/{config_id}/risk/port?port=70000").status_code == 422


def test_unknown_config_returns_404():
    assert client.get("/api/v1/configs/nope/risk").status_code == 404
