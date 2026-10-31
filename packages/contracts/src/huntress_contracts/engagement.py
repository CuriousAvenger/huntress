"""Engagement and durable-checkpoint contracts."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, field_validator, model_validator

from .base import Contract, ensure_utc
from .enums import ActorType, EngagementMode, EngagementState
from .policy import BudgetLimits


class Engagement(Contract):
    """Durable engagement header. State changes go through the controller."""

    engagement_id: str = Field(pattern=r"^eng_[a-zA-Z0-9_-]{6,80}$")
    name: str = Field(min_length=1, max_length=200)
    mode: EngagementMode
    state: EngagementState = EngagementState.CREATED
    program_id: str | None = Field(default=None, max_length=120)
    scope_id: str | None = Field(default=None, pattern=r"^scope_[a-zA-Z0-9_-]{6,80}$")
    scope_version: int = Field(default=0, ge=0)
    policy_version: str = Field(default="unsealed", max_length=80)
    created_at: datetime
    updated_at: datetime
    created_by: str = Field(min_length=1, max_length=200)
    budget_limits: BudgetLimits = BudgetLimits()
    notes: str = Field(default="", max_length=4000)
    labels: tuple[str, ...] = ()
    closed_at: datetime | None = None
    terminal_reason: str | None = Field(default=None, max_length=200)

    _engagement_utc = field_validator("created_at", "updated_at")(ensure_utc)

    @field_validator("closed_at")
    @classmethod
    def _closed_utc(cls, value: datetime | None) -> datetime | None:
        return ensure_utc(value) if value is not None else None

    @model_validator(mode="after")
    def _ordered(self) -> Engagement:
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")
        if self.scope_version > 0 and self.scope_id is None:
            raise ValueError("scope_version requires scope_id")
        if self.state in {
            EngagementState.READY,
            EngagementState.RECON,
            EngagementState.ANALYSIS,
            EngagementState.ACTION_PENDING,
            EngagementState.WAITING_FOR_APPROVAL,
            EngagementState.EXECUTING,
            EngagementState.VALIDATING,
            EngagementState.HUMAN_REVIEW,
            EngagementState.REPORT_DRAFT,
            EngagementState.SUBMISSION_PENDING,
            EngagementState.CLOSED,
        } and self.scope_id is None:
            raise ValueError(f"state {self.state} requires an approved scope")
        return self


class StateTransition(Contract):
    """One audited lifecycle edge."""

    transition_id: str = Field(pattern=r"^trn_[a-zA-Z0-9_-]{6,80}$")
    engagement_id: str = Field(pattern=r"^eng_[a-zA-Z0-9_-]{6,80}$")
    from_state: EngagementState
    to_state: EngagementState
    reason: str = Field(min_length=1, max_length=1000)
    actor_type: ActorType
    actor_id: str = Field(min_length=1, max_length=200)
    occurred_at: datetime
    correlation_id: str = Field(min_length=1, max_length=120)

    _transition_utc = field_validator("occurred_at")(ensure_utc)

    @model_validator(mode="after")
    def _different(self) -> StateTransition:
        if self.from_state is self.to_state:
            raise ValueError("state transition must change state")
        return self


class Checkpoint(Contract):
    """A resumable application checkpoint. Payloads are small and secret-free."""

    checkpoint_id: str = Field(pattern=r"^ckpt_[a-zA-Z0-9_-]{6,80}$")
    engagement_id: str = Field(pattern=r"^eng_[a-zA-Z0-9_-]{6,80}$")
    state: EngagementState
    created_at: datetime
    correlation_id: str = Field(min_length=1, max_length=120)
    payload: dict[str, str | int | float | bool] = Field(default_factory=dict)
    note: str = Field(default="", max_length=1000)

    _checkpoint_utc = field_validator("created_at")(ensure_utc)

    @model_validator(mode="after")
    def _payload_bounded(self) -> Checkpoint:
        if len(self.payload) > 50:
            raise ValueError("checkpoint payload may not exceed 50 keys")
        return self
