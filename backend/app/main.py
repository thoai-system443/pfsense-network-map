from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import configs, inventory, maps, query
from app.settings import settings

app = FastAPI(
    title="pfSense Network Map",
    docs_url="/api/v1/docs",
    redoc_url="/api/v1/redoc",
    openapi_url="/api/v1/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

v1 = APIRouter(prefix="/api/v1")


@v1.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


v1.include_router(configs.router)
v1.include_router(inventory.router)
v1.include_router(maps.router)
v1.include_router(query.router)

app.include_router(v1)
