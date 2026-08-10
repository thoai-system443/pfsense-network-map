"""In-memory store of parsed configurations.

There is no database by design: a pfSense backup is a single document that
parses in milliseconds. The trade-off is that state lives in one process, so
the API must run with a single uvicorn worker.
"""

import uuid
from collections import OrderedDict

from pydantic import BaseModel

from app.parser.types import ParsedConfig, ParseWarning
from app.settings import settings


class ConfigMeta(BaseModel):
    config_id: str
    filename: str
    version: str | None
    hostname: str
    counts: dict[str, int]
    warnings: list[ParseWarning]


class ConfigStore:
    def __init__(self, max_items: int) -> None:
        self.max_items = max_items
        self._items: OrderedDict[str, tuple[ParsedConfig, ConfigMeta]] = OrderedDict()

    def put(self, config: ParsedConfig, filename: str) -> str:
        config_id = uuid.uuid4().hex
        meta = ConfigMeta(
            config_id=config_id,
            filename=filename,
            version=config.version,
            hostname=config.hostname,
            counts={
                "interfaces": len(config.interfaces),
                "aliases": len(config.aliases),
                "rules": len(config.rules),
                "port_forwards": len(config.nat.port_forwards),
                "tunnels": len(config.vpn.tunnels),
            },
            warnings=config.warnings,
        )
        self._items[config_id] = (config, meta)
        while len(self._items) > self.max_items:
            self._items.popitem(last=False)
        return config_id

    def get(self, config_id: str) -> ParsedConfig:
        config, _ = self._items[config_id]
        self._items.move_to_end(config_id)
        return config

    def meta(self, config_id: str) -> ConfigMeta:
        _, meta = self._items[config_id]
        self._items.move_to_end(config_id)
        return meta

    def delete(self, config_id: str) -> None:
        self._items.pop(config_id, None)


config_store = ConfigStore(max_items=settings.max_configs)
