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


def test_report_lists_exposures_per_address():
    body = client.get(f"/api/v1/configs/{upload('risky.xml')}/risk").json()
    lan = next(e for e in body["exposures"] if e["subject"]["id"] == "lan")
    assert lan["cidr"], "every finding names the address it is about"
    assert lan["reaches_internet"] is True
    assert "DMZ" in lan["reaches_networks_any_port"]


def test_the_report_is_computed_once_and_reused(monkeypatch):
    """Equal output proves nothing on its own — count the actual work."""
    from app.engine import risk

    config_id = upload("risky.xml")
    client.get(f"/api/v1/configs/{config_id}/risk")

    calls = 0
    real = risk.exposures

    def counted(config):
        nonlocal calls
        calls += 1
        return real(config)

    monkeypatch.setattr(risk, "exposures", counted)
    second = client.get(f"/api/v1/configs/{config_id}/risk").json()

    assert calls == 0, "the second call recomputed the report"
    assert second["exposures"]


def test_adding_a_firewall_drops_the_cached_report():
    config_id = upload("routed.xml")
    before = client.get(f"/api/v1/configs/{config_id}/risk").json()
    with (FIXTURES / "core.xml").open("rb") as handle:
        client.post(
            f"/api/v1/configs/{config_id}/firewalls",
            files={"file": ("core.xml", handle, "text/xml")},
        )
    after = client.get(f"/api/v1/configs/{config_id}/risk").json()
    assert after != before, "a stale report would hide the firewall just loaded"


def test_report_lists_deny_all_findings():
    body = client.get(f"/api/v1/configs/{upload('risky.xml')}/risk").json()
    kinds = {f["kind"] for f in body["deny_all"]}
    assert {"block-all-not-quick", "unreachable-rule"} <= kinds


def test_port_search_lists_sources():
    config_id = upload("risky.xml")
    body = client.get(f"/api/v1/configs/{config_id}/risk/port?port=5432&protocol=tcp").json()
    assert "DMZ" in {r["source_label"] for r in body}


def test_port_search_keeps_inbound_internet_exposure_by_default():
    config_id = upload("risky.xml")
    body = client.get(f"/api/v1/configs/{config_id}/risk/port?port=8443&protocol=tcp").json()
    assert "Internet" in {r["source_label"] for r in body}


def test_port_search_can_show_outbound_internet_traffic_on_request():
    config_id = upload("risky.xml")
    hidden = client.get(f"/api/v1/configs/{config_id}/risk/port?port=443&protocol=tcp").json()
    shown = client.get(
        f"/api/v1/configs/{config_id}/risk/port"
        "?port=443&protocol=tcp&hide_internet_destinations=false"
    ).json()
    assert sum(len(r["destination_cidrs"]) for r in shown) > sum(
        len(r["destination_cidrs"]) for r in hidden
    )


def test_port_search_rejects_a_port_out_of_range():
    config_id = upload("risky.xml")
    assert client.get(f"/api/v1/configs/{config_id}/risk/port?port=70000").status_code == 422


def test_unknown_config_returns_404():
    assert client.get("/api/v1/configs/nope/risk").status_code == 404


def test_a_neighbour_firewalls_subnet_is_not_reported_as_internet():
    """routed.xml reaches 10.20.5.0/24, which core.xml carries. Judged alone,
    the edge firewall calls that the internet."""
    config_id = upload("routed.xml")
    with (FIXTURES / "core.xml").open("rb") as handle:
        client.post(
            f"/api/v1/configs/{config_id}/firewalls",
            files={"file": ("core.xml", handle, "text/xml")},
        )
    body = client.get(f"/api/v1/configs/{config_id}/risk").json()

    from app.engine import risk
    from app.parser.loader import parse_config

    edge = parse_config((FIXTURES / "routed.xml").read_bytes())
    alone = {e.cidr for e in risk.exposures(edge) if e.reaches_internet}
    together = {
        e["cidr"] for e in body["exposures"] if e["firewall"] == "fw-edge" and e["reaches_internet"]
    }
    assert together <= alone, "loading a neighbour can only remove internet findings"
