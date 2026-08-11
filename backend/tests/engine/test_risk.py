from pathlib import Path

from app.engine import risk
from app.parser.loader import parse_config

FIXTURES = Path(__file__).parent.parent / "fixtures"


def load(name: str):
    return parse_config((FIXTURES / name).read_bytes())


def exposure(config, subject_id: str):
    return next(e for e in risk.exposures(config) if e.subject.id == subject_id)


class TestSubjects:
    def test_every_enabled_interface_is_a_subject(self):
        ids = {s.id for s in risk.subjects(load("risky.xml"))}
        assert {"lan", "opt1", "opt2", "wan"} <= ids

    def test_aliases_are_subjects_too(self):
        subjects = risk.subjects(load("risky.xml"))
        db = next(s for s in subjects if s.id == "alias:DB_SERVER")
        assert db.cidrs == ["10.10.20.50/32"]

    def test_disabled_interfaces_are_left_out(self):
        ids = {s.id for s in risk.subjects(load("vlan_vpn.xml"))}
        assert "opt2" not in ids


class TestReachesOtherSubnetsOnEveryPort:
    def test_flags_a_zone_with_unrestricted_lateral_access(self):
        found = exposure(load("risky.xml"), "lan")
        assert "DMZ" in found.reaches_other_subnets_any_port

    def test_a_single_open_port_is_not_enough(self):
        """LAN reaches the internet on 443 only, so that is not 'any port'."""
        found = exposure(load("risky.xml"), "lan")
        assert "Internet" not in found.reaches_other_subnets_any_port

    def test_a_zone_with_no_lateral_access_is_not_flagged(self):
        assert exposure(load("risky.xml"), "opt2").reaches_other_subnets_any_port == []


class TestReachesInternet:
    def test_flags_the_zone_and_names_the_ports(self):
        found = exposure(load("risky.xml"), "lan")
        assert found.reaches_internet is True
        assert "443" in found.internet_ports

    def test_a_locked_down_zone_does_not_reach_the_internet(self):
        assert exposure(load("risky.xml"), "opt2").reaches_internet is False


class TestReachableFromInternet:
    def test_flags_a_published_host_and_names_the_ports(self):
        found = exposure(load("risky.xml"), "alias:DB_SERVER")
        assert found.reachable_from_internet is True
        assert "8443" in found.inbound_internet_ports

    def test_an_unpublished_zone_is_not_flagged(self):
        assert exposure(load("risky.xml"), "lan").reachable_from_internet is False


class TestReachableFromEveryInternalZone:
    def test_a_zone_nothing_can_reach_is_not_flagged(self):
        assert exposure(load("risky.xml"), "opt2").reachable_from_all_internal is False

    def test_internet_is_not_counted_as_an_internal_source(self):
        """The criterion is about internal blast radius, so WAN-sourced traffic
        must not make a host look reachable from everywhere inside."""
        found = exposure(load("risky.xml"), "alias:DB_SERVER")
        assert found.reachable_from_internet is True
        assert found.reachable_from_all_internal is False


class TestPortReachability:
    def test_lists_who_can_reach_a_port(self):
        results = risk.port_reachability(load("risky.xml"), 5432, "tcp")
        sources = {r.source_label for r in results}
        assert "DMZ" in sources

    def test_names_the_destination_reached_on_that_port(self):
        results = risk.port_reachability(load("risky.xml"), 5432, "tcp")
        assert any("10.10.20.50" in cidr for r in results for cidr in r.destination_cidrs)

    def test_a_port_nobody_allows_returns_nothing(self):
        """basic.xml only ever permits 443, so nothing reaches 9999.

        risky.xml is the wrong fixture for this: it lets LAN into the DMZ on
        every port, so 9999 is genuinely reachable there.
        """
        assert risk.port_reachability(load("basic.xml"), 9999, "tcp") == []

    def test_a_wide_open_zone_shows_up_for_every_port(self):
        """LAN reaches DMZ on all ports, so it must appear for an arbitrary one."""
        results = risk.port_reachability(load("risky.xml"), 4444, "tcp")
        assert "LAN" in {r.source_label for r in results}


class TestDenyAllAudit:
    def test_flags_a_block_all_that_does_not_stop_evaluation(self):
        findings = risk.deny_all_audit(load("risky.xml"))
        leaky = next(f for f in findings if f.kind == "block-all-not-quick")
        assert leaky.rule.descr == "Block everything on DMZ"
        assert leaky.interface == "opt1"

    def test_flags_rules_stranded_behind_a_terminal_block_all(self):
        findings = risk.deny_all_audit(load("risky.xml"))
        dead = next(f for f in findings if f.kind == "unreachable-rule")
        assert dead.rule.descr == "GUEST web access that never runs"
        assert dead.interface == "opt2"

    def test_a_plain_interface_raises_neither_finding(self):
        findings = risk.deny_all_audit(load("basic.xml"))
        assert findings == []
