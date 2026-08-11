"""Turn config.xml bytes into a ParsedConfig.

Unknown elements are reported rather than skipped. This project has never been
run against a real pfSense backup, so the warning list is the mechanism that
surfaces schema gaps on first contact with real data.

Parsing goes through defusedxml because the bytes come from an upload. The
stdlib parser expands internal entities, which makes a billion-laughs payload a
denial of service, and it is the only untrusted input this service accepts.
"""

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from app.parser.aliases import parse_aliases
from app.parser.interfaces import parse_interfaces
from app.parser.nat import parse_nat
from app.parser.routing import parse_gateways, parse_static_routes
from app.parser.rules import parse_rules
from app.parser.types import ParsedConfig
from app.parser.vpn import parse_vpn
from app.parser.xmlutil import WarningCollector, text_of

KNOWN_ROOT_CHILDREN = {
    "version",
    "system",
    "interfaces",
    "vlans",
    "aliases",
    "filter",
    "nat",
    "openvpn",
    "ipsec",
    "dhcpd",
    "dhcpdv6",
    "unbound",
    "snmpd",
    "syslog",
    "widgets",
    "revision",
    "shaper",
    "gateways",
    "staticroutes",
    "ntpd",
    "rrd",
    "cert",
    "ca",
    "sysctl",
    "installedpackages",
    "ppps",
    "wireless",
    "captiveportal",
    "dnshaper",
    "hasync",
    "load_balancer",
    "virtualip",
    "ifgroups",
}


def parse_config(data: bytes) -> ParsedConfig:
    try:
        root = ElementTree.fromstring(data)
    except (ElementTree.ParseError, DefusedXmlException) as exc:
        raise ValueError(f"file is not valid XML: {exc}") from exc

    if root.tag != "pfsense":
        raise ValueError(f"root element is <{root.tag}>, expected <pfsense>")

    warnings = WarningCollector()
    warnings.check_children(root, "pfsense", KNOWN_ROOT_CHILDREN)

    system = root.find("system")
    config = ParsedConfig(
        version=text_of(root, "version"),
        hostname=(text_of(system, "hostname", "") if system is not None else "") or "",
    )
    config.interfaces = parse_interfaces(root, warnings)
    config.aliases = parse_aliases(root, warnings)
    config.rules = parse_rules(root, warnings)
    config.nat = parse_nat(root, warnings)
    config.vpn = parse_vpn(root, warnings)
    config.gateways = parse_gateways(root, warnings)
    config.static_routes = parse_static_routes(root, warnings)
    config.warnings = warnings.items
    return config
