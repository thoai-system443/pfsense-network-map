"""Serve the two graphs."""

from fastapi import APIRouter

from app.api.v1.configs import FirewallsDep
from app.engine import fabric

router = APIRouter(prefix="/configs/{config_id}", tags=["maps"])


@router.get("/topology")
def topology(firewalls: FirewallsDep) -> dict:
    return fabric.topology(firewalls)


@router.get("/access-graph")
def access_graph(firewalls: FirewallsDep, protocol: str = "any") -> dict:
    return fabric.access_graph(firewalls, protocol)
