"""List the objects a configuration contains."""

from fastapi import APIRouter
from pydantic import BaseModel

from app.api.v1.configs import ConfigDep
from app.engine import ruleset
from app.engine.resolver import AliasCycleError, Resolver
from app.parser.types import FilterRule, Interface, NatConfig

router = APIRouter(prefix="/configs/{config_id}", tags=["inventory"])


class ResolvedAlias(BaseModel):
    name: str
    type: str
    items: list[str]
    descr: str
    resolved_addresses: list[str] | None = None
    resolved_ports: str | None = None
    error: str | None = None


@router.get("/interfaces", response_model=list[Interface])
def interfaces(config: ConfigDep) -> list[Interface]:
    return config.interfaces


@router.get("/aliases", response_model=list[ResolvedAlias])
def aliases(config: ConfigDep, resolved: bool = False) -> list[ResolvedAlias]:
    resolver = Resolver(config)
    out: list[ResolvedAlias] = []
    for alias in config.aliases:
        entry = ResolvedAlias(**alias.model_dump())
        if resolved:
            try:
                if alias.type == "port":
                    ports, _ = resolver.expand_alias_ports(alias.name)
                    entry.resolved_ports = ports.to_spec()
                else:
                    addresses, _ = resolver.expand_alias(alias.name, 4)
                    entry.resolved_addresses = addresses.to_cidrs()
            except AliasCycleError as exc:
                entry.error = str(exc)
        out.append(entry)
    return out


@router.get("/rules", response_model=list[FilterRule])
def rules(config: ConfigDep, interface: str | None = None) -> list[FilterRule]:
    if interface:
        return ruleset.build(config, interface)
    return config.rules


@router.get("/nat", response_model=NatConfig)
def nat(config: ConfigDep) -> NatConfig:
    return config.nat
