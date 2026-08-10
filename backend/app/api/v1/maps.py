"""Serve the two graphs."""

from fastapi import APIRouter

from app.api.v1.configs import ConfigDep
from app.engine import graph

router = APIRouter(prefix="/configs/{config_id}", tags=["maps"])


@router.get("/topology")
def topology(config: ConfigDep) -> dict:
    return graph.topology(config)


@router.get("/access-graph")
def access_graph(config: ConfigDep, protocol: str = "any") -> dict:
    return graph.access_graph(config, protocol)
