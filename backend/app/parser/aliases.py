"""Parse <aliases>.

Members are stored space-separated in a single <address> element. A member can
be a literal address, a CIDR, a port, a port range, or the name of another
alias; the parser keeps them verbatim and leaves expansion to the resolver.
"""

from app.parser.types import Alias
from app.parser.xmlutil import WarningCollector, text_of

KNOWN_ALIAS_CHILDREN = {"name", "type", "address", "descr", "detail", "url", "updatefreq"}
VALID_TYPES = {"host", "network", "port", "url", "urltable"}


def parse_aliases(root, warnings: WarningCollector) -> list[Alias]:
    section = root.find("aliases")
    if section is None:
        return []

    out: list[Alias] = []
    for node in section.findall("alias"):
        path = "pfsense/aliases/alias"
        warnings.check_children(node, path, KNOWN_ALIAS_CHILDREN)
        name = text_of(node, "name")
        if not name:
            warnings.add(path, "alias without a name, ignored", "error")
            continue

        kind = text_of(node, "type", "host")
        if kind not in VALID_TYPES:
            warnings.add(f"{path}[{name}]", f"unknown alias type {kind!r}, treated as host")
            kind = "host"

        if kind in {"url", "urltable"}:
            url = text_of(node, "url", "") or ""
            warnings.add(
                f"{path}[{name}]",
                f"alias type {kind!r} needs a network fetch and cannot be resolved offline",
            )
            items = [url] if url else []
        else:
            items = (text_of(node, "address", "") or "").split()

        out.append(Alias(name=name, type=kind, items=items, descr=text_of(node, "descr", "") or ""))
    return out
