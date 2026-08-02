"""Application configuration (12-factor, env-driven, validated).

All settings come from environment variables prefixed ``SEPHELA_`` (or a local
``.env`` file). Import the singleton ``settings`` everywhere; never read
``os.environ`` directly.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["local", "dev", "staging", "prod"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SEPHELA_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ---- Application ----
    env: Environment = "local"
    debug: bool = False
    project_name: str = "Sephela"
    api_v1_prefix: str = "/api/v1"

    # ---- Logging ----
    log_level: str = "INFO"
    log_json: bool = True

    # ---- Security (placeholder auth for Phase 2) ----
    secret_key: str = "change-me"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    cors_origins: str = "http://localhost:3000"

    # ---- PostgreSQL ----
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_user: str = "sephela"
    postgres_password: str = "sephela"
    postgres_db: str = "sephela"

    # ---- Redis ----
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0

    # ---- Storage ----
    storage_backend: Literal["local", "s3"] = "local"
    storage_local_root: str = "./data/storage"
    # S3 settings (used when storage_backend=s3; wired fully in a later phase)
    s3_endpoint_url: str | None = None
    s3_bucket: str = "sephela-samples"
    s3_access_key: str | None = None
    s3_secret_key: str | None = None
    s3_region: str = "us-east-1"

    # ---- Upload / pipeline ----
    max_upload_bytes: int = 300 * 1024 * 1024  # 300 MiB
    pipeline_version: str = "2026.1"

    # ---- Dynamic analysis / sandbox (Phase 10) ----
    # Off by default: the sandbox executes malware and needs a KVM-capable,
    # egress-firewalled host (docs/architecture/02-services.md, 09-security.md).
    dynamic_enabled: bool = False
    sandbox_runner: Literal["disabled", "compose", "script"] = "disabled"
    sandbox_dir: str = "../infra/sandbox"
    sandbox_timeout_secs: int = 180
    # Extra wall-clock beyond the in-script timeout, for emulator boot + cleanup.
    sandbox_timeout_grace_secs: int = 300
    sandbox_api_level: int = 33
    dynamic_artifacts_root: str = "./data/dynamic"
    # Keep artifacts after a run for debugging; disable in prod (they came from a
    # machine that ran malware).
    dynamic_keep_artifacts: bool = False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_prod(self) -> bool:
        return self.env == "prod"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def database_url(self) -> str:
        """Async SQLAlchemy DSN (asyncpg driver)."""
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sync_database_url(self) -> str:
        """Sync DSN used by Alembic migrations."""
        return (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def redis_url(self) -> str:
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
