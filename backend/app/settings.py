from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    cors_origins: list[str] = ["http://localhost:8080"]
    max_upload_bytes: int = 16 * 1024 * 1024
    max_configs: int = 20


settings = Settings()
