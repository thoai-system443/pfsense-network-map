import json
from typing import Annotated

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # NoDecode is required, not decorative. Without it pydantic-settings
    # JSON-decodes the env value inside the settings source, before any
    # validator runs, and every non-JSON spelling dies there as a SettingsError.
    cors_origins: Annotated[list[str], NoDecode] = ["http://localhost:8011"]
    max_upload_bytes: int = 16 * 1024 * 1024
    max_configs: int = 20

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _parse_origins(cls, value: object) -> object:
        """Accept a JSON array, a comma-separated list, or one bare origin.

        pydantic-settings only parses a list[str] field as JSON, so
        CORS_ORIGINS=http://localhost:8011 would otherwise crash the process at
        startup — the moment furthest from the request that needed it.
        """
        if not isinstance(value, str):
            return value
        text = value.strip()
        if text.startswith("["):
            # Parsed here rather than left to pydantic-settings, which only
            # applies JSON decoding to env sources. Doing it here keeps env vars
            # and direct constructor arguments behaving the same way.
            try:
                return json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"CORS origins looked like JSON but did not parse: {exc}") from exc
        return [part.strip() for part in text.split(",") if part.strip()]

    @field_validator("cors_origins", mode="after")
    @classmethod
    def _check_origins(cls, origins: list[str]) -> list[str]:
        """An origin is scheme://host[:port] and nothing else.

        A browser sends Origin with no trailing slash and no path, so anything
        else here silently never matches and the failure surfaces as a confusing
        CORS error in the browser instead of a clear one at startup.
        """
        cleaned: list[str] = []
        for origin in origins:
            if origin == "*":
                cleaned.append(origin)
                continue
            trimmed = origin.rstrip("/")
            scheme, separator, rest = trimmed.partition("://")
            if not separator or not scheme or not rest or "/" in rest:
                raise ValueError(f"CORS origin {origin!r} is not of the form scheme://host[:port]")
            cleaned.append(trimmed)
        return cleaned


settings = Settings()
