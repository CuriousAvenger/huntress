"""Runtime configuration for the Huntress controller.

Settings are flat so they map cleanly to ``HUNTRESS_*`` environment variables
and to the reviewed ``config/defaults.toml`` file. Secrets are accepted only as
``SecretStr`` values or via the environment; they are never written to audit
records, checkpoints, or model context.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, ClassVar

from huntress_contracts import BudgetLimits, EngagementMode
from huntress_contracts import ExecutionBackend as BackendMode
from huntress_governance import load_or_create_signing_key
from huntress_reasoning import ModelSettings
from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)

DEFAULT_CONFIG_FILE = Path("config/defaults.toml")


class Settings(BaseSettings):
    """Validated application settings with environment > TOML > defaults."""

    model_config = SettingsConfigDict(
        env_prefix="HUNTRESS_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        protected_namespaces=(),
    )

    _toml_file: ClassVar[Path | None] = None

    # Runtime and paths -----------------------------------------------------
    data_dir: Path = Path(".huntress")
    db_path: Path | None = None
    artifact_dir: Path | None = None
    signing_key_file: Path | None = None
    signing_key_value: SecretStr | None = None
    mode: EngagementMode = EngagementMode.LAB
    operator: str = Field(default="local-operator", min_length=1, max_length=200)
    log_level: str = Field(default="INFO", max_length=20)

    # Model provider --------------------------------------------------------
    model_provider: str = "openai_compatible"
    model_id: str = Field(default="local-model", min_length=1, max_length=200)
    model_base_url: str | None = "http://127.0.0.1:1234/v1"
    model_api_key: SecretStr | None = None
    model_api_key_env: str | None = "OPENAI_API_KEY"
    model_region: str | None = None
    model_temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    model_max_tokens: int = Field(default=2048, ge=1, le=200_000)
    model_context_window: int | None = Field(default=None, ge=1)
    model_timeout_seconds: float = Field(default=120.0, gt=0.0)
    model_max_turns: int = Field(default=4, ge=1, le=32)
    model_total_token_limit: int = Field(default=24_000, ge=0)
    model_input_cost_per_million: float = Field(default=0.0, ge=0.0)
    model_output_cost_per_million: float = Field(default=0.0, ge=0.0)

    # Exegol MCP ------------------------------------------------------------
    exegol_backend: BackendMode = BackendMode.AUTO
    exegol_url: str = "http://127.0.0.1:2187/mcp"
    exegol_token: SecretStr | None = None
    exegol_container: str = Field(default="pentest", min_length=1, max_length=120)
    exegol_timeout_seconds: float = Field(default=300.0, gt=0.0)
    exegol_max_output_bytes: int = Field(default=1_048_576, ge=1024)
    exegol_allow_remote: bool = False

    # Budgets and limits ----------------------------------------------------
    max_actions_per_engagement: int = Field(default=200, ge=1, le=100_000)
    max_model_calls_per_engagement: int = Field(default=50, ge=0, le=10_000)
    max_tokens_per_engagement: int = Field(default=500_000, ge=0, le=100_000_000)
    max_cost_usd_per_engagement: float = Field(default=5.0, ge=0.0, le=100_000.0)
    max_wall_clock_seconds: int = Field(default=7200, ge=1, le=2_592_000)
    max_requests_per_host_per_minute: int = Field(default=30, ge=1, le=600)
    max_requests_per_engagement_per_minute: int = Field(default=60, ge=1, le=3000)
    max_concurrency: int = Field(default=2, ge=1, le=16)
    approval_ttl_seconds: int = Field(default=3600, ge=60, le=86_400)

    # Evidence --------------------------------------------------------------
    evidence_max_artifact_bytes: int = Field(default=10_485_760, ge=1024)
    evidence_retention_days: int = Field(default=90, ge=1, le=3650)

    # Reasoning -------------------------------------------------------------
    reasoning_enabled: bool = False
    reasoning_max_context_chars: int = Field(default=120_000, ge=1000, le=1_000_000)
    reasoning_context_excerpt_chars: int = Field(default=1200, ge=0, le=4000)
    reasoning_max_evidence_items: int = Field(default=40, ge=1, le=200)

    # Local lab -------------------------------------------------------------
    lab_host: str = "127.0.0.1"
    lab_port: int = Field(default=8000, ge=0, le=65535)

    @field_validator("model_provider")
    @classmethod
    def _provider_lower(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("data_dir", "db_path", "artifact_dir", "signing_key_file")
    @classmethod
    def _expand_path(cls, value: Path | None) -> Path | None:
        return value.expanduser() if value is not None else None

    @model_validator(mode="after")
    def _safety_invariants(self) -> Settings:
        if self.mode is not EngagementMode.LAB and self.exegol_backend is BackendMode.FAKE:
            raise ValueError("the fake execution backend is only permitted in lab mode")
        if self.reasoning_enabled and self.max_model_calls_per_engagement < 1:
            raise ValueError("reasoning requires at least one model call in the engagement budget")
        return self

    # Derived paths ---------------------------------------------------------
    @property
    def database_path(self) -> Path:
        return (self.db_path or self.data_dir / "huntress.db").expanduser()

    @property
    def artifacts_path(self) -> Path:
        return (self.artifact_dir or self.data_dir / "artifacts").expanduser()

    @property
    def signing_key_path(self) -> Path:
        return (self.signing_key_file or self.data_dir / "signing.key").expanduser()

    def ensure_directories(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.artifacts_path.mkdir(parents=True, exist_ok=True)
        self.signing_key_path.parent.mkdir(parents=True, exist_ok=True)

    # Contract conversions --------------------------------------------------
    def budget_limits(self) -> BudgetLimits:
        return BudgetLimits(
            max_actions=self.max_actions_per_engagement,
            max_model_calls=self.max_model_calls_per_engagement,
            max_tokens=self.max_tokens_per_engagement,
            max_cost_usd=self.max_cost_usd_per_engagement,
            max_wall_clock_seconds=self.max_wall_clock_seconds,
            max_requests_per_host_per_minute=self.max_requests_per_host_per_minute,
            max_requests_per_engagement_per_minute=self.max_requests_per_engagement_per_minute,
            max_concurrency=self.max_concurrency,
        )

    def model_settings(self) -> ModelSettings:
        return ModelSettings(
            provider=self.model_provider,
            model_id=self.model_id,
            base_url=self.model_base_url,
            api_key_env=self.model_api_key_env,
            region=self.model_region,
            temperature=self.model_temperature,
            max_output_tokens=self.model_max_tokens,
            context_window=self.model_context_window,
            timeout_seconds=self.model_timeout_seconds,
            input_cost_per_million=self.model_input_cost_per_million,
            output_cost_per_million=self.model_output_cost_per_million,
        )

    def model_environment(self) -> dict[str, str]:
        """Environment passed to the model factory, including an explicit key."""

        environment = dict(os.environ)
        if self.model_api_key is not None and self.model_api_key_env:
            environment[self.model_api_key_env] = self.model_api_key.get_secret_value()
        return environment

    def exegol_token_value(self) -> str | None:
        if self.exegol_token is None:
            return None
        value = self.exegol_token.get_secret_value().strip()
        return value or None

    def signing_key_bytes(self) -> bytes:
        if self.signing_key_value is not None:
            key = self.signing_key_value.get_secret_value().encode("utf-8")
            if len(key) < 32:
                raise ValueError("HUNTRESS_SIGNING_KEY must be at least 32 bytes")
            return key
        return load_or_create_signing_key(self.signing_key_path)

    # Pydantic settings sources --------------------------------------------
    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        sources: list[PydanticBaseSettingsSource] = [
            init_settings,
            env_settings,
            dotenv_settings,
        ]
        path = cls._toml_file
        if path is not None and path.exists():
            sources.append(TomlConfigSettingsSource(settings_cls, toml_file=path))
        sources.append(file_secret_settings)
        return tuple(sources)


def load_settings(
    config_file: Path | str | None = None,
    **overrides: Any,
) -> Settings:
    """Load settings with an explicit TOML file or the repository default."""

    candidate = config_file
    if candidate is None:
        candidate = os.environ.get("HUNTRESS_CONFIG_FILE") or DEFAULT_CONFIG_FILE
    Settings._toml_file = Path(candidate).expanduser()
    return Settings(**overrides)
