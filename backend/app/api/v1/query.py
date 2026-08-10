"""The three reachability queries."""

import ipaddress
from dataclasses import asdict

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.api.v1.configs import ConfigDep
from app.engine import evaluate
from app.engine.resolver import AliasCycleError, Resolver
from app.parser.types import AddrSpec, ParsedConfig

router = APIRouter(prefix="/configs/{config_id}/query", tags=["query"])


class CheckRequest(BaseModel):
    source: str
    destination: str
    port: int | None = None
    protocol: str = "any"


class FromRequest(BaseModel):
    source: str
    protocol: str = "any"


class ToRequest(BaseModel):
    destination: str
    port: int | None = None
    protocol: str = "any"


def to_probe_address(config: ParsedConfig, token: str) -> str:
    """Accept an address, a CIDR, an interface name, or an alias, and pick one address."""
    resolver = Resolver(config)
    try:
        addresses, _ = resolver.addresses(AddrSpec(network=token), 4)
    except AliasCycleError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if addresses.is_empty():
        raise HTTPException(status_code=400, detail=f"cannot resolve {token!r} to an address")

    lo, hi = addresses.items[0]
    return str(ipaddress.ip_address(lo + 1 if lo < hi else lo))


@router.post("/check")
def check(request: CheckRequest, config: ConfigDep) -> dict:
    source = to_probe_address(config, request.source)
    destination = to_probe_address(config, request.destination)
    result = evaluate.check(config, source, destination, request.port, request.protocol)
    return {
        "verdict": result.verdict,
        "decided_by": asdict(result.decided_by) if result.decided_by else None,
        "in_interface": result.in_interface,
        "translated_address": result.translated_address,
        "translated_port": result.translated_port,
        "unresolved": result.unresolved,
        "trace": [
            {"rule": asdict(e.rule), "matched": e.matched, "reason": e.reason} for e in result.trace
        ],
    }


@router.post("/from")
def query_from(request: FromRequest, config: ConfigDep) -> list[dict]:
    source = to_probe_address(config, request.source)
    return [
        {
            "addresses": region.addresses,
            "ports": region.ports,
            "verdict": region.verdict,
            "decided_by": asdict(region.decided_by) if region.decided_by else None,
        }
        for region in evaluate.explore_from(config, source, request.protocol)
    ]


@router.post("/to")
def query_to(request: ToRequest, config: ConfigDep) -> list[dict]:
    destination = to_probe_address(config, request.destination)
    return [
        {
            "in_interface": region.in_interface,
            "addresses": region.addresses,
            "verdict": region.verdict,
            "decided_by": asdict(region.decided_by) if region.decided_by else None,
        }
        for region in evaluate.explore_to(config, destination, request.port, request.protocol)
    ]
