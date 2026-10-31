"""Provider-agnostic model configuration and Strands model factory.

Secrets are never stored in settings. ``api_key_env`` names an environment
variable that is read at construction time; the resulting model object holds
the client credentials in memory only.
"""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from strands.models.model import Model

from .errors import MissingCredential, UnknownProvider

SUPPORTED_PROVIDERS = frozenset({"openai_compatible", "openai", "anthropic", "bedrock", "ollama", "litellm"})


@dataclass(frozen=True, slots=True)
class ModelSettings:
    """Runtime model selection with no secret material."""

    provider: str = "openai_compatible"
    model_id: str = "local-model"
    base_url: str | None = "http://127.0.0.1:1234/v1"
    api_key_env: str | None = "OPENAI_API_KEY"
    region: str | None = None
    temperature: float = 0.0
    max_output_tokens: int = 1024
    context_window: int | None = None
    timeout_seconds: float = 120.0
    input_cost_per_million: float = 0.0
    output_cost_per_million: float = 0.0

    def __post_init__(self) -> None:
        provider = self.provider.strip().lower()
        if provider not in SUPPORTED_PROVIDERS:
            raise UnknownProvider(f"unsupported model provider: {self.provider!r}")
        object.__setattr__(self, "provider", provider)
        if not self.model_id.strip():
            raise ValueError("model_id must not be empty")
        if not 0.0 <= self.temperature <= 2.0:
            raise ValueError("temperature must be between 0 and 2")
        if not 1 <= self.max_output_tokens <= 200_000:
            raise ValueError("max_output_tokens must be between 1 and 200000")
        if self.context_window is not None and self.context_window < 1:
            raise ValueError("context_window must be positive")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.input_cost_per_million < 0 or self.output_cost_per_million < 0:
            raise ValueError("token costs must not be negative")
        if self.base_url is not None and not self.base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must be an absolute http(s) URL")


def _is_loopback(url: str | None) -> bool:
    if not url:
        return False
    host = urlsplit(url).hostname
    if host is None:
        return False
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _require_key(settings: ModelSettings, env: Mapping[str, str]) -> str:
    if settings.api_key_env:
        value = env.get(settings.api_key_env)
        if value:
            return value
    raise MissingCredential(
        f"provider {settings.provider!r} requires environment variable {settings.api_key_env!r} to be set"
    )


def create_model(
    settings: ModelSettings,
    *,
    env: Mapping[str, str] | None = None,
) -> Model:
    """Construct the configured Strands model without making a network call."""

    environment = env if env is not None else os.environ
    provider = settings.provider

    if provider == "openai_compatible":
        from strands.models.openai import OpenAIModel

        key = None
        if settings.api_key_env:
            key = environment.get(settings.api_key_env)
        if not key and _is_loopback(settings.base_url):
            key = "lm-studio"
        if not key:
            raise MissingCredential("openai_compatible requires an API key or a loopback base_url")
        client_args: dict[str, object] = {"api_key": key, "timeout": settings.timeout_seconds}
        if settings.base_url:
            client_args["base_url"] = settings.base_url
        return OpenAIModel(
            client_args=client_args,
            model_id=settings.model_id,
            params={
                "temperature": settings.temperature,
                "max_tokens": settings.max_output_tokens,
            },
            context_window_limit=settings.context_window,
            stream=False,
        )

    if provider == "openai":
        from strands.models.openai import OpenAIModel

        client_args = {
            "api_key": _require_key(settings, environment),
            "timeout": settings.timeout_seconds,
        }
        if settings.base_url:
            client_args["base_url"] = settings.base_url
        return OpenAIModel(
            client_args=client_args,
            model_id=settings.model_id,
            params={
                "temperature": settings.temperature,
                "max_tokens": settings.max_output_tokens,
            },
            context_window_limit=settings.context_window,
            stream=False,
        )

    if provider == "anthropic":
        from strands.models.anthropic import AnthropicModel

        return AnthropicModel(
            client_args={
                "api_key": _require_key(settings, environment),
                "timeout": settings.timeout_seconds,
            },
            model_id=settings.model_id,
            max_tokens=settings.max_output_tokens,
            params={"temperature": settings.temperature},
            context_window_limit=settings.context_window,
        )

    if provider == "bedrock":
        from strands.models.bedrock import BedrockModel

        return BedrockModel(
            region_name=settings.region,
            model_id=settings.model_id,
            max_tokens=settings.max_output_tokens,
            temperature=settings.temperature,
            context_window_limit=settings.context_window,
        )

    if provider == "ollama":
        from strands.models.ollama import OllamaModel

        return OllamaModel(
            settings.base_url or "http://127.0.0.1:11434",
            model_id=settings.model_id,
            temperature=settings.temperature,
            max_tokens=settings.max_output_tokens,
        )

    if provider == "litellm":
        from strands.models.litellm import LiteLLMModel

        lite_client_args: dict[str, object] = {}
        if settings.api_key_env and environment.get(settings.api_key_env):
            lite_client_args["api_key"] = environment[settings.api_key_env]
        return LiteLLMModel(
            client_args=lite_client_args,
            model_id=settings.model_id,
            params={
                "temperature": settings.temperature,
                "max_tokens": settings.max_output_tokens,
            },
            context_window_limit=settings.context_window,
        )

    raise UnknownProvider(f"unsupported model provider: {provider!r}")  # pragma: no cover
