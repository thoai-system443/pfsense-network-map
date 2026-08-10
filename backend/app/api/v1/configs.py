"""Upload, inspect, and drop configurations."""

from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, Response, UploadFile

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


# Annotated rather than a default argument: calling Depends()/File() in a
# default is what ruff's B008 flags, and this is the form FastAPI recommends.
ConfigDep = Annotated[ParsedConfig, Depends(get_config)]
UploadDep = Annotated[UploadFile, File()]


@router.post("", response_model=ConfigMeta, status_code=201)
async def upload(file: UploadDep) -> ConfigMeta:
    data = await file.read()
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="file too large")
    try:
        config = parse_config(data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    config_id = config_store.put(config, file.filename or "config.xml")
    return config_store.meta(config_id)


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
