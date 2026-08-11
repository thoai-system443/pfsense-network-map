"""One config id now holds a set of firewalls, not a single file."""

from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

FIXTURES = Path(__file__).parent.parent / "fixtures"
client = TestClient(app)


def upload(name: str) -> dict:
    with (FIXTURES / name).open("rb") as handle:
        return client.post("/api/v1/configs", files={"file": (name, handle, "text/xml")}).json()


def add(config_id: str, name: str):
    with (FIXTURES / name).open("rb") as handle:
        return client.post(
            f"/api/v1/configs/{config_id}/firewalls", files={"file": (name, handle, "text/xml")}
        )


def two_firewalls() -> str:
    config_id = upload("routed.xml")["config_id"]
    add(config_id, "core.xml")
    return config_id


class TestAddingFirewalls:
    def test_the_first_upload_creates_a_workspace_with_one_firewall(self):
        body = upload("routed.xml")
        assert [f["name"] for f in body["firewalls"]] == ["fw-edge"]

    def test_a_second_file_joins_the_same_workspace(self):
        config_id = upload("routed.xml")["config_id"]
        body = add(config_id, "core.xml").json()
        assert [f["name"] for f in body["firewalls"]] == ["fw-edge", "fw-core"]

    def test_counts_cover_every_firewall(self):
        config_id = two_firewalls()
        body = client.get(f"/api/v1/configs/{config_id}").json()
        assert body["counts"]["interfaces"] == 5

    def test_warnings_say_which_firewall_raised_them(self):
        config_id = upload("unresolvable_alias.xml")["config_id"]
        body = client.get(f"/api/v1/configs/{config_id}").json()
        assert all("firewall" in w for w in body["warnings"])

    def test_adding_to_an_unknown_workspace_is_404(self):
        assert add("nope", "core.xml").status_code == 404

    def test_a_broken_second_file_does_not_damage_the_workspace(self):
        config_id = upload("routed.xml")["config_id"]
        bad = client.post(
            f"/api/v1/configs/{config_id}/firewalls",
            files={"file": ("bad.xml", b"<pfsense><oops>", "text/xml")},
        )
        assert bad.status_code == 400
        body = client.get(f"/api/v1/configs/{config_id}").json()
        assert len(body["firewalls"]) == 1


class TestPathQuery:
    def test_reports_every_hop(self):
        config_id = two_firewalls()
        body = client.post(
            f"/api/v1/configs/{config_id}/query/path",
            json={
                "source": "192.168.1.50",
                "destination": "10.20.5.10",
                "port": 443,
                "protocol": "tcp",
            },
        ).json()
        assert body["verdict"] == "pass"
        assert [h["firewall_name"] for h in body["hops"]] == ["fw-edge", "fw-core"]

    def test_a_downstream_block_decides_the_whole_path(self):
        config_id = two_firewalls()
        body = client.post(
            f"/api/v1/configs/{config_id}/query/path",
            json={
                "source": "192.168.1.50",
                "destination": "10.20.5.10",
                "port": 22,
                "protocol": "tcp",
            },
        ).json()
        assert body["verdict"] == "block"
        assert body["hops"][0]["verdict"] == "pass"
        assert body["hops"][1]["firewall_name"] == "fw-core"

    def test_says_when_the_chain_ran_off_the_edge_of_what_is_loaded(self):
        config_id = two_firewalls()
        body = client.post(
            f"/api/v1/configs/{config_id}/query/path",
            json={
                "source": "192.168.1.50",
                "destination": "8.8.8.8",
                "port": 443,
                "protocol": "tcp",
            },
        ).json()
        assert body["truncated"] is True
        assert "203.0.113.1" in body["stopped_reason"]


class TestMergedInventory:
    def test_interfaces_from_both_firewalls_are_listed_and_tagged(self):
        config_id = two_firewalls()
        body = client.get(f"/api/v1/configs/{config_id}/interfaces").json()
        assert {row["firewall"] for row in body} == {"fw-edge", "fw-core"}

    def test_rules_from_both_firewalls_are_listed_and_tagged(self):
        config_id = two_firewalls()
        body = client.get(f"/api/v1/configs/{config_id}/rules").json()
        assert {row["firewall"] for row in body} == {"fw-edge", "fw-core"}

    def test_a_shared_subnet_is_one_node_on_the_topology(self):
        config_id = two_firewalls()
        body = client.get(f"/api/v1/configs/{config_id}/topology").json()
        transit = [n for n in body["nodes"] if n.get("subnet") == "10.10.20.0/24"]
        assert len(transit) == 1

    def test_the_topology_has_a_node_per_firewall(self):
        config_id = two_firewalls()
        body = client.get(f"/api/v1/configs/{config_id}/topology").json()
        assert {n["label"] for n in body["nodes"] if n["kind"] == "firewall"} == {
            "fw-edge",
            "fw-core",
        }
