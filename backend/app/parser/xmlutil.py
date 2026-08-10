"""Shared XML helpers.

These live apart from loader.py so the per-section parsers can use them without
importing loader, which imports the parsers in turn.
"""

from app.parser.types import ParseWarning, Severity


class WarningCollector:
    def __init__(self) -> None:
        self.items: list[ParseWarning] = []

    def add(self, path: str, message: str, severity: Severity = "warning") -> None:
        self.items.append(ParseWarning(path=path, message=message, severity=severity))

    def check_children(self, element, path: str, known: set[str]) -> None:
        for child in element:
            if child.tag not in known:
                self.add(f"{path}/{child.tag}", "unrecognised element, ignored")


def text_of(element, tag: str, default: str | None = None) -> str | None:
    found = element.find(tag)
    if found is None:
        return default
    return (found.text or "").strip() or default


def has_flag(element, tag: str) -> bool:
    """pfSense writes booleans as empty elements: <enable></enable>."""
    return element.find(tag) is not None
