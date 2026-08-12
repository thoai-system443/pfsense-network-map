"""Risk analysis derived from the reachability engine."""

from dataclasses import asdict

from fastapi import APIRouter, Query

from app.api.v1.configs import WorkspaceDep
from app.engine import risk
from app.engine.ipset import IpSet
from app.engine.portset import MAX_PORT

router = APIRouter(prefix="/configs/{config_id}/risk", tags=["risk"])


# Declared before the bare "" route so FastAPI matches the literal path first.
@router.get("/port")
def by_port(
    workspace: WorkspaceDep,
    port: int = Query(ge=0, le=MAX_PORT),
    protocol: str = "any",
    hide_internet_destinations: bool = True,
) -> list[dict]:
    return [
        {**asdict(entry), "firewall": firewall.name}
        for firewall in workspace.firewalls
        for entry in risk.port_reachability(
            firewall.config, port, protocol, hide_internet_destinations
        )
    ]


@router.get("")
def report(workspace: WorkspaceDep) -> dict:
    """Per firewall, tagged.

    The four criteria are answered against one firewall's own ruleset; a zone
    behind a second firewall is analysed there. Cross-firewall reachability is
    what the path query on the Search page answers.

    Cached on the workspace: the report is the most expensive thing this API
    computes and the configs it reads never change, so a reload should not pay
    for it twice.
    """
    return workspace.cached("risk-report", lambda: _report(workspace.firewalls))


def _report(firewalls) -> dict:
    # Every firewall is judged knowing the whole site. Alone, each one treats
    # its neighbours' subnets as the internet and reports exposure that is not
    # there.
    known = {
        firewall.id: risk.internal_space(firewall.config) for firewall in firewalls
    }

    def elsewhere(firewall):
        space = IpSet.empty(4)
        for other_id, other in known.items():
            if other_id != firewall.id:
                space = space.union(other)
        return space

    return {
        "exposures": [
            {**asdict(entry), "firewall": firewall.name}
            for firewall in firewalls
            for entry in risk.exposures(firewall.config, also_internal=elsewhere(firewall))
        ],
        "deny_all": [
            {**asdict(entry), "firewall": firewall.name}
            for firewall in firewalls
            for entry in risk.deny_all_audit(firewall.config)
        ],
    }
