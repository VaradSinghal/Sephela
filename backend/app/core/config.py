"""Application configuration (12-factor, env-driven, validated).

All settings come from environment variables prefixed ``SEPHELA_`` (or a local
``.env`` file). Import the singleton ``settings`` everywhere; never read
``os.environ`` directly.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal
from urllib.parse import quote

from pydantic import computed_field
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

    # ---- Security ----
    # secret_key signs every token. The default is a placeholder that the app
    # refuses to boot with outside local/test — see _assert_production_ready.
    secret_key: str = "change-me"
    algorithm: str = "HS256"
    # Access tokens are short so a leaked one expires quickly; refresh tokens carry
    # the session length and are rotated on every use.
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    cors_origins: str = "http://localhost:3000"

    # ---- Rate limiting (per-principal, sliding window) ----
    rate_limit_enabled: bool = True
    rate_limit_requests: int = 300
    rate_limit_window_seconds: int = 60
    # Uploads cost far more than a status poll, so they get their own tighter bucket.
    rate_limit_upload_requests: int = 20
    rate_limit_upload_window_seconds: int = 60

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
    # Optional so a local stack needs no credential, but a deployed Redis holds the
    # job queues — every pending analysis and its sample id — so it must require
    # auth. Left unset here rather than defaulted to a placeholder, because an
    # insecure default would be silently accepted in prod.
    redis_password: str | None = None

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

    # ---- Threat intelligence (Phase 11) ----
    # On by default, unlike dynamic analysis: two of the five feeds (URLhaus,
    # MalwareBazaar) are keyless, so the stage produces real evidence with zero
    # configuration. Setting no API keys degrades coverage, not correctness.
    threat_intel_enabled: bool = True
    # Per-provider API keys. An absent key omits that provider entirely rather
    # than failing the stage (app.services.threat_intel.build_providers).
    virustotal_api_key: str | None = None
    otx_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    # abuse.ch services are keyless historically; newer deployments issue keys.
    urlhaus_api_key: str | None = None
    bazaar_api_key: str | None = None
    # Ceiling on *live* provider calls per job. Cache hits are free and do not
    # count. Sized so one pathological sample cannot drain a day's free quota.
    threat_intel_max_lookups: int = 200
    threat_intel_concurrency: int = 8
    threat_intel_timeout_secs: float = 20.0
    # Consecutive failures before a provider is dropped for the rest of the run.
    threat_intel_breaker_threshold: int = 4
    # Multiplier on the engine's per-IoC-type cache TTLs. Lower it to re-check
    # verdicts more often (costs quota); raise it to stretch a small quota.
    threat_intel_cache_ttl_factor: float = 1.0

    # ---- Engine workspace (static/code-intel scratch space) ----
    # Where engines that need the sample on disk unpack it. Separate from
    # dynamic_artifacts_root, which the sandbox owns and wipes.
    engine_workspace_root: str = "./data/workspace"
    # Keep decompiled trees after a run for debugging; disable in prod (they are
    # derived from a malware sample).
    keep_engine_artifacts: bool = False
    # Upper bound on the compressed decompiled-source archive the static stage hands to
    # code intel through object storage. A tree over the cap is skipped rather than
    # failing the stage: code intel then runs without it, which costs call-graph and
    # control-flow depth and never correctness. 256 MiB of gzipped Java is a very large
    # APK; the cap exists so one pathological sample cannot fill the bucket.
    max_decompiled_archive_bytes: int = 256 * 1024 * 1024

    # ---- Feature flags (Phase-gated capabilities) ----
    # Toggle each capability per environment.
    #
    # The default-on stages are the ones that need no external credential and no
    # sandbox: static extraction, code intelligence, and the two deterministic
    # stages that turn findings into a score and a report. ai_enabled is the
    # exception — it is the only stage that cannot run without a paid LLM key, so
    # it would fail every job on a fresh deployment rather than degrade.
    static_enabled: bool = True
    code_intel_enabled: bool = True
    ai_enabled: bool = False
    scoring_enabled: bool = True
    reporting_enabled: bool = True
    rag_enabled: bool = False
    multi_agent_enabled: bool = False

    # ---- Observability (OpenTelemetry + Prometheus) ----
    otel_enabled: bool = False
    otel_service_name: str = "sephela-api"
    otel_exporter_endpoint: str | None = None  # e.g. http://localhost:4317
    metrics_enabled: bool = False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_prod(self) -> bool:
        return self.env == "prod"

    def _pg_dsn(self, driver: str) -> str:
        """Build a Postgres DSN with credentials percent-encoded.

        A generated password containing '@', '/', or ':' would otherwise be parsed as
        part of the host or port, producing a connection attempt against the wrong
        address rather than an authentication failure — a confusing outage from a
        correct password.
        """
        user = quote(self.postgres_user, safe="")
        secret = quote(self.postgres_password, safe="")
        return (
            f"postgresql+{driver}://{user}:{secret}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def database_url(self) -> str:
        """Async SQLAlchemy DSN (asyncpg driver)."""
        return self._pg_dsn("asyncpg")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sync_database_url(self) -> str:
        """Sync DSN used by Alembic migrations."""
        return self._pg_dsn("psycopg")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def redis_url(self) -> str:
        # quote() the password: Redis passwords are generated blobs that routinely
        # contain '@' or '/', either of which silently truncates the DSN and produces
        # a confusing "wrong host" failure rather than an auth error.
        if self.redis_password:
            secret = quote(self.redis_password, safe="")
            return f"redis://:{secret}@{self.redis_host}:{self.redis_port}/{self.redis_db}"
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


# Values that are fine locally and unacceptable in a deployed environment. Each is
# a footgun that fails silently rather than loudly: a default signing key still
# produces valid-looking tokens, so nothing breaks until someone forges one.
_INSECURE_DEFAULTS = {
    "secret_key": "change-me",
    "postgres_password": "sephela",
}

# RFC 7518 §3.2: an HMAC key must be at least the hash output size — 32 bytes for
# HS256. Shorter keys still sign and verify, so this is the same class of silent
# footgun as the placeholders above: nothing looks broken until someone brute-forces
# the key. .env.example already asks for 32+; this is what makes it a requirement.
_MIN_HMAC_KEY_BYTES = 32


def assert_production_ready(config: Settings) -> None:
    """Refuse to run a deployed environment on placeholder secrets.

    Raises:
        ConfigurationError: if any insecure default survives outside ``local``.

    ``local`` is the only exemption: requiring real secrets to run the test suite or
    a laptop stack would get this check deleted rather than satisfied. Every other
    environment in the ``Environment`` literal — including ``dev`` — is a deployed
    K8s namespace (doc 08) and must supply its own.
    """
    if config.env == "local":
        return

    offenders = [
        name
        for name, insecure in _INSECURE_DEFAULTS.items()
        if getattr(config, name, None) == insecure
    ]
    if offenders:
        from app.core.exceptions import ConfigurationError

        raise ConfigurationError(
            f"Refusing to start in env='{config.env}' with default "
            f"{', '.join(sorted(offenders))}. Supply real secrets."
        )

    # A non-default but too-short key passes the check above and still weakens every
    # token: `SEPHELA_SECRET_KEY=hunter2` is not a placeholder, just inadequate.
    # Only HS* uses secret_key as raw HMAC material; RS*/ES* carry a PEM instead.
    if config.algorithm.startswith("HS"):
        key_bytes = len(config.secret_key.encode())
        if key_bytes < _MIN_HMAC_KEY_BYTES:
            from app.core.exceptions import ConfigurationError

            raise ConfigurationError(
                f"Refusing to start in env='{config.env}': secret_key is {key_bytes} "
                f"bytes, below the {_MIN_HMAC_KEY_BYTES} required for "
                f"{config.algorithm} (RFC 7518 §3.2). Supply a longer secret."
            )

    # Local-disk storage on a deployed environment is the same class of silent
    # misconfiguration as a placeholder secret: nothing errors, and every stage that
    # lands on a different worker than the upload simply cannot find the sample. It
    # presents as intermittent "APK bytes missing from storage" rather than as the
    # configuration mistake it is.
    if config.storage_backend == "local":
        from app.core.exceptions import ConfigurationError

        raise ConfigurationError(
            f"Refusing to start in env='{config.env}' with storage_backend='local'. "
            f"A deployed environment runs more than one worker and local disk is not "
            f"shared between them; set SEPHELA_STORAGE_BACKEND=s3."
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
