from pathlib import Path

from app.parser.loader import parse_config

FIXTURES = Path(__file__).parent.parent / "fixtures"


def load(name: str):
    return parse_config((FIXTURES / name).read_bytes())


def test_splits_space_separated_addresses():
    alias = load("alias_nested.xml").alias_by_name("DB_HOSTS")
    assert alias.items == ["192.168.1.20", "192.168.1.21"]


def test_reads_port_alias_including_ranges():
    alias = load("alias_nested.xml").alias_by_name("MGMT_PORTS")
    assert (alias.type, alias.items) == ("port", ["22", "3389", "5900-5910"])


def test_nested_alias_keeps_member_names_verbatim():
    assert load("alias_nested.xml").alias_by_name("TIER_TWO").items == [
        "DB_HOSTS",
        "APP_HOSTS",
    ]


def test_urltable_alias_stores_url_and_warns():
    config = load("unresolvable_alias.xml")
    assert config.alias_by_name("BLOCKLIST").items == ["https://example.com/list.txt"]
    assert any("offline" in w.message for w in config.warnings)
