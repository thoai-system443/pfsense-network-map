from pathlib import Path

import pytest

from app.parser.loader import parse_config

FIXTURES = Path(__file__).parent.parent / "fixtures"


def load(name: str):
    return parse_config((FIXTURES / name).read_bytes())


def test_reads_version():
    assert load("basic.xml").version == "22.5"


def test_basic_fixture_produces_no_warnings():
    assert load("basic.xml").warnings == []


def test_unknown_element_becomes_a_warning():
    xml = b"""<?xml version="1.0"?>
<pfsense><version>22.5</version><totally_unknown_section/></pfsense>"""
    warnings = parse_config(xml).warnings
    assert len(warnings) == 1
    assert warnings[0].path == "pfsense/totally_unknown_section"


def test_malformed_xml_raises():
    with pytest.raises(ValueError, match="not valid XML"):
        parse_config(b"<pfsense><unclosed>")


def test_wrong_root_element_raises():
    with pytest.raises(ValueError, match="root element"):
        parse_config(b"<?xml version='1.0'?><notpfsense/>")


def test_entity_expansion_bomb_is_rejected():
    """Uploads are untrusted input; expat would otherwise expand this."""
    bomb = b"""<?xml version="1.0"?>
<!DOCTYPE pfsense [
  <!ENTITY a "aaaaaaaaaa">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
]>
<pfsense><version>&c;</version></pfsense>"""
    with pytest.raises(ValueError, match="not valid XML"):
        parse_config(bomb)


def test_external_entity_is_rejected():
    payload = b"""<?xml version="1.0"?>
<!DOCTYPE pfsense [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<pfsense><version>&xxe;</version></pfsense>"""
    with pytest.raises(ValueError, match="not valid XML"):
        parse_config(payload)
