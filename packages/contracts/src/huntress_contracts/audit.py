"""Append-only audit contracts with a SHA-256 hash chain."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, field_validator, model_validator

from .base import Contract, ensure_utc
from .enums import ActorType


class Actor(Contract):
    """Who or what caused an event. Agent identity is never an authority."""

    type: ActorType
    id: str = Field(min_length=1, max_length=200)


class AuditEvent(Contract):
    """Structured audit record. ``details`` must never contain secrets.

    ``event_hash = sha256(canonical_json(event without event_hash))`` and
    ``prev_hash`` links to the previous event in the same engagement chain.
    """

    event_id: str = Field(pattern=r"^aud_[a-zA-Z0-9_-]{6,80}$")
    occurred_at: datetime
    engagement_id: str | None = Field(default=None, pattern=r"^eng_[a-zA-Z0-9_-]{6,80}$")
    actor: Actor
    action: str = Field(min_length=1, max_length=120)
    outcome: str = Field(min_length=1, max_length=80)
    correlation_id: str = Field(min_length=1, max_length=120)
    policy_version: str | None = Field(default=None, max_length=80)
    model_id: str | None = Field(default=None, max_length=200)
    tool_profile: str | None = Field(default=None, max_length=120)
    details: dict[str, str | int | float | bool] = Field(default_factory=dict)
    prev_hash: str = Field(default="", max_length=64)
    event_hash: str = Field(default="", max_length=64)

    _occurred_utc = field_validator("occurred_at")(ensure_utc)

    @model_validator(mode="after")
    def _details_bounded(self) -> AuditEvent:
        if len(self.details) > 60:
            raise ValueError("audit details may not exceed 60 keys")
        for key, value in self.details.items():
            if len(key) > 80:
                raise ValueError("audit detail key too long")
            if isinstance(value, str) and len(value) > 1000:
                raise ValueError("audit detail value too long")
        return self


class AuditChainVerification(Contract):
    """Result of verifying an engagement's audit chain."""

    engagement_id: str | None = None
    events_checked: int = Field(ge=0)
    valid: bool
    first_invalid_event_id: str | None = None
    reason: str = Field(default="", max_length=1000)
    checked_at: datetime

    _checked_utc = field_validator("checked_at")(ensure_utc)
