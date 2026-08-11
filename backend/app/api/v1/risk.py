"""Risk analysis derived from the reachability engine."""

from dataclasses import asdict

from fastapi import APIRouter, Query

from app.api.v1.configs import ConfigDep
from app.engine import risk
from app.engine.portset import MAX_PORT

router = APIRouter(prefix="/configs/{config_id}/risk", tags=["risk"])


# Declared before the bare "" route so FastAPI matches the literal path first.
@router.get("/port")
def by_port(
    config: ConfigDep,
    port: int = Query(ge=0, le=MAX_PORT),
    protocol: str = "any",
) -> list[dict]:
    return [asdict(entry) for entry in risk.port_reachability(config, port, protocol)]


@router.get("")
def report(config: ConfigDep) -> dict:
    return {
        "exposures": [asdict(entry) for entry in risk.exposures(config)],
        "unoccupied_grants": [asdict(entry) for entry in risk.unoccupied_grants(config)],
        "deny_all": [asdict(entry) for entry in risk.deny_all_audit(config)],
    }
