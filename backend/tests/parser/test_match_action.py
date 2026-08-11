"""The `match` action, and outbound NAT fields, found in a real pfSense backup.

`match` is what floating shaper rules use. It assigns a queue and lets
evaluation continue; it never decides a verdict. The first version of this
parser folded every unrecognised action into `block`, which turned a
match-everything shaper rule into a firewall that blocked everything — the tool
would report traffic as denied while the firewall was letting it through.
"""

from pathlib import Path

from app.engine.evaluate import check, explore_from
from app.parser.loader import parse_config

FIXTURES = Path(__file__).parent.parent / "fixtures"


def load(name: str):
    return parse_config((FIXTURES / name).read_bytes())


class TestParsing:
    def test_match_is_a_recognised_action(self):
        assert load("match_rule.xml").rules[0].action == "match"

    def test_match_does_not_produce_a_warning(self):
        warnings = load("match_rule.xml").warnings
        assert not any("unknown rule type" in w.message for w in warnings)

    def test_outbound_nat_fields_are_recognised(self):
        warnings = load("match_rule.xml").warnings
        assert not any("unrecognised" in w.message for w in warnings)


class TestEvaluation:
    def test_a_match_rule_never_decides_the_verdict(self):
        result = check(load("match_rule.xml"), "192.168.1.50", "8.8.8.8", 443, "tcp")
        assert result.verdict == "pass"
        assert result.decided_by.descr == "Allow LAN to any HTTPS"

    def test_traffic_the_match_rule_covers_still_falls_to_default_deny(self):
        """The shaper rule matches port 9999 too, but it must not grant anything."""
        result = check(load("match_rule.xml"), "192.168.1.50", "8.8.8.8", 9999, "tcp")
        assert result.verdict == "block"
        assert result.decided_by is None

    def test_the_match_rule_is_still_listed_in_the_trace(self):
        """It is evaluated, so hiding it would misrepresent the ruleset."""
        result = check(load("match_rule.xml"), "192.168.1.50", "8.8.8.8", 443, "tcp")
        assert "Shape all LAN traffic" in [entry.rule.descr for entry in result.trace]

    def test_explore_agrees_with_the_point_check(self):
        config = load("match_rule.xml")
        regions = explore_from(config, "192.168.1.50", "tcp")
        allowed = [r for r in regions if r.verdict == "pass"]
        assert any(r.ports == "443" for r in allowed)
        assert not any(r.decided_by and r.decided_by.action == "match" for r in regions)
