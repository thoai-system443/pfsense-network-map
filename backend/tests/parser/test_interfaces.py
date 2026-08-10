from pathlib import Path

from app.parser.loader import parse_config

FIXTURES = Path(__file__).parent.parent / "fixtures"


def load(name: str):
    return parse_config((FIXTURES / name).read_bytes())


def test_reads_all_interfaces():
    names = [i.name for i in load("vlan_vpn.xml").interfaces]
    assert names == ["wan", "lan", "opt1", "opt2"]


def test_uses_descr_as_display_name():
    dmz = load("vlan_vpn.xml").interface_by_name("opt1")
    assert dmz.descr == "DMZ"


def test_reads_address_and_prefix():
    lan = load("vlan_vpn.xml").interface_by_name("lan")
    assert (lan.ipaddr, lan.subnet) == ("192.168.1.1", 24)


def test_interface_without_enable_flag_is_disabled():
    assert load("vlan_vpn.xml").interface_by_name("opt2").enabled is False


def test_vlan_interface_is_linked_to_parent():
    dmz = load("vlan_vpn.xml").interface_by_name("opt1")
    assert (dmz.is_vlan, dmz.vlan_tag, dmz.parent_if) == (True, 20, "em2")


def test_plain_interface_is_not_marked_vlan():
    assert load("vlan_vpn.xml").interface_by_name("lan").is_vlan is False
