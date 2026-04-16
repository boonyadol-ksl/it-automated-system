from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class ServerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="KSL_", extra="ignore")

    host: str = "127.0.0.1"
    port: int = 8800
    log_level: str = "info"

    api_key: str = "change-me"
    database_url: str = "sqlite:///./data/ksl_itops.db"

