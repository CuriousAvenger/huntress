"""Model-call accounting contracts.

Prompts, private reasoning text, and raw model responses are not evidence and
are not stored in these records. ``output_ref`` points at a hash-addressed
structured artifact when retention is explicitly enabled.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import Field, field_validator, model_validator

from .base import Contract, ensure_utc
from .enums import ContextTask, ModelCallStatus


class ModelCallRecord(Contract):
    """Bounded telemetry for one model invocation."""

    call_id: str = Field(pattern=r"^mc_[a-zA-Z0-9_-]{6,80}$")
    engagement_id: str = Field(pattern=r"^eng_[a-zA-Z0-9_-]{6,80}$")
    checkpoint: ContextTask
    provider: str = Field(min_length=1, max_length=80)
    model_id: str = Field(min_length=1, max_length=200)
    prompt_version: str = Field(min_length=1, max_length=80)
    context_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    started_at: datetime
    finished_at: datetime
    status: ModelCallStatus
    stop_reason: str = Field(default="", max_length=80)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cost_usd: Annotated[float, Field(ge=0.0)] = 0.0
    output_schema: str = Field(default="", max_length=200)
    output_ref: str | None = Field(default=None, max_length=128)
    error_code: str | None = Field(default=None, max_length=80)
    error_message: str = Field(default="", max_length=2000)

    _call_utc = field_validator("started_at", "finished_at")(ensure_utc)

    @model_validator(mode="after")
    def _ordered(self) -> ModelCallRecord:
        if self.finished_at < self.started_at:
            raise ValueError("finished_at must not precede started_at")
        if self.status is ModelCallStatus.SUCCEEDED and self.error_code:
            raise ValueError("successful call must not carry an error code")
        return self
