"""Risk analysis derived from the reachability engine."""

from dataclasses import asdict

from fastapi import APIRouter, Query

from app.api.v1.configs import FirewallsDep
from app.engine import risk
from app.engine.portset import MAX_PORT

router = APIRouter(prefix="/configs/{config_id}/risk", tags=["risk"])


# Declared before the bare "" route so FastAPI matches the literal path first.
@router.get("/port")
def by_port(
    firewalls: FirewallsDep,
    port: int = Query(ge=0, le=MAX_PORT),
    protocol: str = "any",
    internal_only: bool = True,
) -> list[dict]:
    return [
        {**asdict(entry), "firewall": firewall.name}
        for firewall in firewalls
        for entry in risk.port_reachability(firewall.config, port, protocol, internal_only)
    ]


@router.get("")
def report(firewalls: FirewallsDep) -> dict:
    """Per firewall, tagged.

    The four criteria are answered against one firewall's own ruleset; a zone
    behind a second firewall is analysed there. Cross-firewall reachability is
    what the path query on the Search page answers.
    """
    return {
        "exposures": [
            {**asdict(entry), "firewall": firewall.name}
            for firewall in firewalls
            for entry in risk.exposures(firewall.config)
        ],
        "deny_all": [
            {**asdict(entry), "firewall": firewall.name}
            for firewall in firewalls
            for entry in risk.deny_all_audit(firewall.config)
        ],
    }
