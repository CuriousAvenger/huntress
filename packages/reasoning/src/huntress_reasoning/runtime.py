"""Provider-agnostic structured-output runtime.

The runtime has no tools and no conversation history. Every invocation receives
one freshly compiled packet and returns one validated Pydantic draft. Provider
and schema failures are translated into ``RuntimeInvocationError`` so the
reasoning service can record telemetry without persisting an invalid decision.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Protocol

from huntress_contracts import ModelCallStatus
from pydantic import BaseModel
from strands import Agent
from strands.models.model import Model
from strands.types.exceptions import StructuredOutputException

from .errors import RuntimeInvocationError
from .factory import ModelSettings, create_model

_LIMIT_STOP_REASONS = frozenset({"limit_turns", "limit_total_tokens", "limit_output_tokens"})


@dataclass(frozen=True, slots=True)
class RuntimeOutput:
    """One successful, schema-validated model response and its usage."""

    output: BaseModel
    stop_reason: str
    input_tokens: int
    output_tokens: int
    latency_seconds: float = 0.0


class StructuredRuntime(Protocol):
    """The only model surface the reasoning service is allowed to use."""

    @property
    def provider(self) -> str: ...

    @property
    def model_id(self) -> str: ...

    @property
    def max_output_tokens(self) -> int: ...

    @property
    def input_cost_per_million(self) -> float: ...

    @property
    def output_cost_per_million(self) -> float: ...

    def invoke(
        self,
        *,
        system_prompt: str,
        prompt: str,
        output_model: type[BaseModel],
    ) -> RuntimeOutput: ...


class StrandsRuntime:
    """A single-agent, tool-free Strands invocation with structured output."""

    def __init__(
        self,
        settings: ModelSettings | None = None,
        *,
        model: Model | None = None,
        max_turns: int = 3,
    ) -> None:
        if max_turns < 1:
            raise ValueError("max_turns must be at least 1")
        self._settings = settings or ModelSettings()
        self._model = model if model is not None else create_model(self._settings)
        self._max_turns = max_turns

    @property
    def provider(self) -> str:
        return self._settings.provider

    @property
    def model_id(self) -> str:
        return self._settings.model_id

    @property
    def max_output_tokens(self) -> int:
        return self._settings.max_output_tokens

    @property
    def input_cost_per_million(self) -> float:
        return self._settings.input_cost_per_million

    @property
    def output_cost_per_million(self) -> float:
        return self._settings.output_cost_per_million

    def invoke(
        self,
        *,
        system_prompt: str,
        prompt: str,
        output_model: type[BaseModel],
    ) -> RuntimeOutput:
        # A fresh agent per call guarantees that no prior transcript, tool state,
        # or model-side memory can influence this packet.
        agent = Agent(
            model=self._model,
            tools=[],
            system_prompt=system_prompt,
            callback_handler=None,
            load_tools_from_directory=False,
        )
        started = time.perf_counter()
        try:
            result = agent(
                prompt,
                structured_output_model=output_model,
                limits={
                    "turns": self._max_turns,
                    "output_tokens": self._settings.max_output_tokens,
                },
            )
        except StructuredOutputException as exc:
            raise RuntimeInvocationError(
                f"model output did not match {output_model.__name__}: {exc}",
                status=ModelCallStatus.INVALID_OUTPUT,
                error_code="structured_output_invalid",
            ) from exc
        except Exception as exc:  # provider/client failures must become telemetry
            raise RuntimeInvocationError(
                f"model provider call failed: {type(exc).__name__}: {exc}",
                status=ModelCallStatus.PROVIDER_ERROR,
                error_code=type(exc).__name__[:80],
            ) from exc

        latency = max(0.0, time.perf_counter() - started)
        usage = result.metrics.accumulated_usage
        input_tokens = max(0, int(usage.get("inputTokens", 0) or 0))
        output_tokens = max(0, int(usage.get("outputTokens", 0) or 0))
        stop_reason = str(result.stop_reason)

        if result.structured_output is None:
            if stop_reason in _LIMIT_STOP_REASONS:
                status = ModelCallStatus.BUDGET_EXCEEDED
                code = "model_loop_limit"
            elif stop_reason == "cancelled":
                status = ModelCallStatus.CANCELLED
                code = "model_cancelled"
            else:
                status = ModelCallStatus.INVALID_OUTPUT
                code = "structured_output_missing"
            raise RuntimeInvocationError(
                f"model returned no structured output (stop_reason={stop_reason})",
                status=status,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                stop_reason=stop_reason,
                error_code=code,
            )

        if not isinstance(result.structured_output, output_model):
            raise RuntimeInvocationError(
                f"model returned {type(result.structured_output).__name__}, expected {output_model.__name__}",
                status=ModelCallStatus.INVALID_OUTPUT,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                stop_reason=stop_reason,
                error_code="structured_output_wrong_type",
            )

        return RuntimeOutput(
            output=result.structured_output,
            stop_reason=stop_reason,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_seconds=latency,
        )
