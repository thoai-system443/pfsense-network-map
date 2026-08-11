"""List the objects a configuration contains."""

from fastapi import APIRouter
from pydantic import BaseModel

from app.api.v1.configs import FirewallsDep
from app.engine import ruleset
from app.engine.resolver import AliasCycleError, Resolver

router = APIRouter(prefix="/configs/{config_id}", tags=["inventory"])


class ResolvedAlias(BaseModel):
    name: str
    type: str
    items: list[str]
    descr: str
    firewall: str = ""
    resolved_addresses: list[str] | None = None
    resolved_ports: str | None = None
    error: str | None = None


@router.get("/interfaces")
def interfaces(firewalls: FirewallsDep) -> list[dict]:
    return [
        {**iface.model_dump(), "firewall": firewall.name}
        for firewall in firewalls
        for iface in firewall.config.interfaces
    ]


@router.get("/aliases", response_model=list[ResolvedAlias])
def aliases(firewalls: FirewallsDep, resolved: bool = False) -> list[ResolvedAlias]:
    out: list[ResolvedAlias] = []
    for firewall in firewalls:
        resolver = Resolver(firewall.config)
        for alias in firewall.config.aliases:
            entry = ResolvedAlias(**alias.model_dump(), firewall=firewall.name)
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


@router.get("/rules")
def rules(firewalls: FirewallsDep, interface: str | None = None) -> list[dict]:
    out: list[dict] = []
    for firewall in firewalls:
        chosen = ruleset.build(firewall.config, interface) if interface else firewall.config.rules
        out.extend({**rule.model_dump(), "firewall": firewall.name} for rule in chosen)
    return out


@router.get("/nat")
def nat(firewalls: FirewallsDep) -> list[dict]:
    return [
        {"firewall": firewall.name, **firewall.config.nat.model_dump()} for firewall in firewalls
    ]
