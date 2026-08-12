"""In-memory store of parsed configurations.

There is no database by design: a pfSense backup is a single document that
parses in milliseconds. The trade-off is that state lives in one process, so
the API must run with a single uvicorn worker.

A stored entry is a workspace, not a file. One config id holds every firewall
loaded for the same network, because answering "can A reach B" across a chain
of firewalls needs all of them at once.
"""

import uuid
from collections import OrderedDict

from pydantic import BaseModel

from app.engine.fabric import Firewall
from app.parser.types import ParsedConfig
from app.settings import settings


class FirewallMeta(BaseModel):
    id: str
    name: str
    filename: str
    version: str | None


class TaggedWarning(BaseModel):
    firewall: str
    path: str
    message: str
    severity: str


class ConfigMeta(BaseModel):
    config_id: str
    filename: str
    version: str | None
    hostname: str
    firewalls: list[FirewallMeta]
    counts: dict[str, int]
    warnings: list[TaggedWarning]


class Workspace:
    def __init__(self, config_id: str) -> None:
        self.config_id = config_id
        self.firewalls: list[Firewall] = []
        self.filenames: dict[str, str] = {}
        # A parsed config never changes, so anything derived from it can be kept
        # for as long as the workspace lives. Adding a firewall is the one event
        # that invalidates it.
        self._derived: dict[str, object] = {}

    def cached(self, key: str, build):
        if key not in self._derived:
            self._derived[key] = build()
        return self._derived[key]

    def add(self, config: ParsedConfig, filename: str) -> Firewall:
        firewall = Firewall(
            id=f"fw-{len(self.firewalls)}",
            # The hostname is what an operator recognises; the filename is only
            # a fallback for a backup that never set one.
            name=config.hostname or filename.removesuffix(".xml"),
            config=config,
        )
        self.firewalls.append(firewall)
        self.filenames[firewall.id] = filename
        self._derived.clear()
        return firewall

    @property
    def primary(self) -> ParsedConfig:
        return self.firewalls[0].config

    def meta(self) -> ConfigMeta:
        counts = {"firewalls": len(self.firewalls)}
        for key, value in (
            ("interfaces", lambda c: len(c.interfaces)),
            ("aliases", lambda c: len(c.aliases)),
            ("rules", lambda c: len(c.rules)),
            ("port_forwards", lambda c: len(c.nat.port_forwards)),
            ("tunnels", lambda c: len(c.vpn.tunnels)),
            ("static_routes", lambda c: len(c.static_routes)),
        ):
            counts[key] = sum(value(firewall.config) for firewall in self.firewalls)

        warnings = [
            TaggedWarning(
                firewall=firewall.name,
                path=warning.path,
                message=warning.message,
                severity=warning.severity,
            )
            for firewall in self.firewalls
            for warning in firewall.config.warnings
        ]

        first = self.firewalls[0]
        return ConfigMeta(
            config_id=self.config_id,
            filename=self.filenames[first.id],
            version=first.config.version,
            hostname=first.config.hostname,
            firewalls=[
                FirewallMeta(
                    id=firewall.id,
                    name=firewall.name,
                    filename=self.filenames[firewall.id],
                    version=firewall.config.version,
                )
                for firewall in self.firewalls
            ],
            counts=counts,
            warnings=warnings,
        )


class ConfigStore:
    def __init__(self, max_items: int) -> None:
        self.max_items = max_items
        self._items: OrderedDict[str, Workspace] = OrderedDict()

    def put(self, config: ParsedConfig, filename: str) -> str:
        config_id = uuid.uuid4().hex
        workspace = Workspace(config_id)
        workspace.add(config, filename)
        self._items[config_id] = workspace
        while len(self._items) > self.max_items:
            self._items.popitem(last=False)
        return config_id

    def workspace(self, config_id: str) -> Workspace:
        workspace = self._items[config_id]
        self._items.move_to_end(config_id)
        return workspace

    def get(self, config_id: str) -> ParsedConfig:
        """The first firewall's config, for the endpoints that work on one."""
        return self.workspace(config_id).primary

    def firewalls(self, config_id: str) -> list[Firewall]:
        return self.workspace(config_id).firewalls

    def meta(self, config_id: str) -> ConfigMeta:
        return self.workspace(config_id).meta()

    def delete(self, config_id: str) -> None:
        self._items.pop(config_id, None)


config_store = ConfigStore(max_items=settings.max_configs)
