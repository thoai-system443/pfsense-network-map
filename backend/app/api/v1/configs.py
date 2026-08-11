"""Upload, inspect, and drop workspaces."""

from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, Response, UploadFile

from app.engine.fabric import Firewall
from app.parser.loader import parse_config
from app.parser.types import ParsedConfig
from app.settings import settings
from app.store import ConfigMeta, config_store

router = APIRouter(prefix="/configs", tags=["configs"])


def get_config(config_id: str) -> ParsedConfig:
    try:
        return config_store.get(config_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="config not found") from None


def get_firewalls(config_id: str) -> list[Firewall]:
    try:
        return config_store.firewalls(config_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="config not found") from None


# Annotated rather than a default argument: calling Depends()/File() in a
# default is what ruff's B008 flags, and this is the form FastAPI recommends.
ConfigDep = Annotated[ParsedConfig, Depends(get_config)]
FirewallsDep = Annotated[list[Firewall], Depends(get_firewalls)]
UploadDep = Annotated[UploadFile, File()]


async def _read_config(file: UploadFile) -> ParsedConfig:
    data = await file.read()
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="file too large")
    try:
        return parse_config(data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("", response_model=ConfigMeta, status_code=201)
async def upload(file: UploadDep) -> ConfigMeta:
    config = await _read_config(file)
    config_id = config_store.put(config, file.filename or "config.xml")
    return config_store.meta(config_id)


@router.post("/{config_id}/firewalls", response_model=ConfigMeta, status_code=201)
async def add_firewall(config_id: str, file: UploadDep) -> ConfigMeta:
    """Load another firewall from the same network into an existing workspace.

    The file is parsed before it is attached, so a bad upload leaves the
    workspace exactly as it was.
    """
    try:
        workspace = config_store.workspace(config_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="config not found") from None
    config = await _read_config(file)
    workspace.add(config, file.filename or "config.xml")
    return workspace.meta()


@router.get("/{config_id}", response_model=ConfigMeta)
def show(config_id: str) -> ConfigMeta:
    try:
        return config_store.meta(config_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="config not found") from None


@router.delete("/{config_id}", status_code=204)
def remove(config_id: str) -> Response:
    config_store.delete(config_id)
    return Response(status_code=204)
