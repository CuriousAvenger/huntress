"""Policy, approval, budget, and action-ledger contracts.

These records are the authority layer. The model may propose an
``ActionRequest``, but only the deterministic ``PolicyGateway`` can produce an
allowing ``PolicyDecision``, and only a human can produce an ``ApprovalRecord``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import Field, field_validator, model_validator

from .base import Contract, ensure_utc
from .enums import (
    ActionKind,
    ApprovalStatus,
    BudgetReservationStatus,
    DecisionSource,
    LedgerStatus,
    ReasonCode,
)

_IDEMPOTENCY_RE = r"^[A-Za-z0-9][A-Za-z0-9:_.-]{7,199}$"


class ActionRequest(Contract):
    """A request to execute one reviewed action against one known target.

    There is intentionally no field for a URL, command, argument, budget, or
    scope mutation. Everything executable is resolved from server-side IDs.
    """

    request_id: str = Field(pattern=r"^req_[a-zA-Z0-9_-]{6,80}$")
    engagement_id: str = Field(pattern=r"^eng_[a-zA-Z0-9_-]{6,80}$")
    action: ActionKind
    target_id: str | None = Field(default=None, pattern=r"^tgt_[a-zA-Z0-9_-]{6,80}$")
    profile_id: str | None = Field(default=None, max_length=120)
    hypothesis_id: str | None = Field(default=None, pattern=r"^hyp_[a-zA-Z0-9_-]{6,80}$")
    evidence_ids: tuple[str, ...] = ()
    idempotency_key: str = Field(pattern=_IDEMPOTENCY_RE)
    requested_by: str = Field(min_length=1, max_length=200)
    requested_at: datetime
    source_decision_id: str | None = Field(default=None, pattern=r"^dec_[a-zA-Z0-9_-]{6,80}$")
    source: DecisionSource = DecisionSource.OPERATOR

    _requested_utc = field_validator("requested_at")(ensure_utc)

    @model_validator(mode="after")
    def _action_shape(self) -> ActionRequest:
        if self.action is ActionKind.RUN_APPROVED_PROFILE:
            if not self.target_id or not self.profile_id:
                raise ValueError("run_approved_profile requires target_id and profile_id")
        elif self.profile_id is not None:
            raise ValueError(f"{self.action} must not reference a profile")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("evidence_ids must be unique")
        return self

    def action_fingerprint(self) -> str:
        """Stable identity of what would execute, independent of request time.

        Approvals and idempotency bind to this, so a retry cannot silently swap
        target or profile while reusing the same approval.
        """

        from .base import sha256_hex

        return sha256_hex(
            f"{self.engagement_id}|{self.action.value}|{self.target_id or ''}|"
            f"{self.profile_id or ''}|{','.join(sorted(self.evidence_ids))}"
        )


class HostRequestCount(Contract):
    host: str = Field(min_length=1, max_length=253)
    requests: int = Field(ge=0)


class BudgetLimits(Contract):
    """Per-engagement ceilings. Reservations are transactional."""

    max_actions: int = Field(default=200, ge=1, le=100_000)
    max_model_calls: int = Field(default=50, ge=0, le=10_000)
    max_tokens: int = Field(default=500_000, ge=0, le=100_000_000)
    max_cost_usd: Annotated[float, Field(ge=0.0, le=100_000.0)] = 5.0
    max_wall_clock_seconds: int = Field(default=7200, ge=1, le=2_592_000)
    max_requests_per_host_per_minute: int = Field(default=30, ge=1, le=600)
    max_requests_per_engagement_per_minute: int = Field(default=60, ge=1, le=3000)
    max_concurrency: int = Field(default=2, ge=1, le=16)


class BudgetUsage(Contract):
    actions_used: int = Field(default=0, ge=0)
    model_calls_used: int = Field(default=0, ge=0)
    tokens_used: int = Field(default=0, ge=0)
    cost_usd_used: float = Field(default=0.0, ge=0.0)
    wall_clock_seconds_used: int = Field(default=0, ge=0)
    requests_total: int = Field(default=0, ge=0)
    host_request_counts: tuple[HostRequestCount, ...] = ()


class BudgetSnapshot(Contract):
    """Point-in-time budget view embedded in every policy decision."""

    limits: BudgetLimits
    usage: BudgetUsage
    remaining_actions: int = Field(ge=0)
    remaining_model_calls: int = Field(ge=0)
    remaining_tokens: int = Field(ge=0)
    remaining_cost_usd: float = Field(ge=0.0)
    remaining_wall_clock_seconds: int = Field(ge=0)
    captured_at: datetime

    _captured_utc = field_validator("captured_at")(ensure_utc)

    @model_validator(mode="after")
    def _consistent(self) -> BudgetSnapshot:
        if self.remaining_actions > self.limits.max_actions:
            raise ValueError("remaining_actions exceeds limit")
        if self.remaining_model_calls > self.limits.max_model_calls:
            raise ValueError("remaining_model_calls exceeds limit")
        if self.remaining_tokens > self.limits.max_tokens:
            raise ValueError("remaining_tokens exceeds limit")
        if self.remaining_cost_usd > self.limits.max_cost_usd + 1e-9:
            raise ValueError("remaining_cost_usd exceeds limit")
        return self


class BudgetReservation(Contract):
    """A transactional hold. It is committed on completion or released on failure."""

    reservation_id: str = Field(pattern=r"^br_[a-zA-Z0-9_-]{6,80}$")
    engagement_id: str = Field(pattern=r"^eng_[a-zA-Z0-9_-]{6,80}$")
    request_id: str = Field(pattern=r"^req_[a-zA-Z0-9_-]{6,80}$")
    idempotency_key: str = Field(pattern=_IDEMPOTENCY_RE)
    host: str | None = Field(default=None, max_length=253)
    requests: int = Field(default=0, ge=0)
    actions: int = Field(default=1, ge=0)
    model_calls: int = Field(default=0, ge=0)
    tokens: int = Field(default=0, ge=0)
    cost_usd: float = Field(default=0.0, ge=0.0)
    status: BudgetReservationStatus = BudgetReservationStatus.RESERVED
    created_at: datetime
    settled_at: datetime | None = None

    _created_utc = field_validator("created_at")(ensure_utc)

    @field_validator("settled_at")
    @classmethod
    def _settled_utc(cls, value: datetime | None) -> datetime | None:
        return ensure_utc(value) if value is not None else None

    @model_validator(mode="after")
    def _host_requests(self) -> BudgetReservation:
        if self.requests > 0 and not self.host:
            raise ValueError("a reservation with requests requires a host")
        return self


class PolicyDecision(Contract):
    """Deterministic verdict. ``allowed`` is the only field execution trusts."""

    decision_id: str = Field(pattern=r"^pol_[a-zA-Z0-9_-]{6,80}$")
    request_id: str = Field(pattern=r"^req_[a-zA-Z0-9_-]{6,80}$")
    engagement_id: str = Field(pattern=r"^eng_[a-zA-Z0-9_-]{6,80}$")
    allowed: bool
    reason_code: ReasonCode
    reasons: tuple[str, ...] = ()
    policy_version: str = Field(min_length=1, max_length=80)
    scope_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    action_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    budget_snapshot: BudgetSnapshot
    requires_approval: bool = False
    approval_id: str | None = Field(default=None, pattern=r"^apr_[a-zA-Z0-9_-]{6,80}$")
    decided_at: datetime
    expires_at: datetime
    decision_hash: str = Field(default="", max_length=64)

    _decided_utc = field_validator("decided_at", "expires_at")(ensure_utc)

    @model_validator(mode="after")
    def _verdict_shape(self) -> PolicyDecision:
        if self.allowed and self.reason_code is not ReasonCode.ALLOWED:
            raise ValueError("an allowed decision must use ReasonCode.ALLOWED")
        if not self.allowed and self.reason_code is ReasonCode.ALLOWED:
            raise ValueError("a denied decision cannot use ReasonCode.ALLOWED")
        if self.allowed and self.expires_at <= self.decided_at:
            raise ValueError("an allowing decision must not be born expired")
        if self.allowed and self.requires_approval and self.approval_id is None:
            raise ValueError("a decision that requires approval must carry a validated approval id")
        return self


class ApprovalRequest(Contract):
    """A pending human gate for one exact action fingerprint."""

    approval_id: str = Field(pattern=r"^apr_[a-zA-Z0-9_-]{6,80}$")
    engagement_id: str = Field(pattern=r"^eng_[a-zA-Z0-9_-]{6,80}$")
    request_id: str = Field(pattern=r"^req_[a-zA-Z0-9_-]{6,80}$")
    action_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    scope_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    requested_by: str = Field(min_length=1, max_length=200)
    requested_at: datetime
    reason: str = Field(min_length=1, max_length=2000)
    status: ApprovalStatus = ApprovalStatus.PENDING
    expires_at: datetime

    _requested_utc = field_validator("requested_at", "expires_at")(ensure_utc)

    @model_validator(mode="after")
    def _window(self) -> ApprovalRequest:
        if self.expires_at <= self.requested_at:
            raise ValueError("approval expires_at must be after requested_at")
        return self


class ApprovalRecord(Contract):
    """A human approval bound to the action fingerprint and scope version.

    Changing the target, profile, evidence set, or scope invalidates it.
    """

    approval_id: str = Field(pattern=r"^apr_[a-zA-Z0-9_-]{6,80}$")
    engagement_id: str = Field(pattern=r"^eng_[a-zA-Z0-9_-]{6,80}$")
    request_id: str = Field(pattern=r"^req_[a-zA-Z0-9_-]{6,80}$")
    action_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    scope_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    approved_by: str = Field(min_length=1, max_length=200)
    approved_at: datetime
    expires_at: datetime
    note: str = Field(default="", max_length=2000)
    status: ApprovalStatus = ApprovalStatus.APPROVED
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature: str = Field(default="", max_length=64)

    _approved_utc = field_validator("approved_at", "expires_at")(ensure_utc)

    @model_validator(mode="after")
    def _window(self) -> ApprovalRecord:
        if self.expires_at <= self.approved_at:
            raise ValueError("approval expires_at must be after approved_at")
        return self


class ActionLedgerEntry(Contract):
    """Idempotency and retry authority for one action fingerprint."""

    idempotency_key: str = Field(pattern=_IDEMPOTENCY_RE)
    request_id: str = Field(pattern=r"^req_[a-zA-Z0-9_-]{6,80}$")
    engagement_id: str = Field(pattern=r"^eng_[a-zA-Z0-9_-]{6,80}$")
    action_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: LedgerStatus
    reserved_at: datetime
    updated_at: datetime
    artifact_refs: tuple[str, ...] = ()
    result_ref: str | None = Field(default=None, max_length=128)
    error_code: str | None = Field(default=None, max_length=80)

    _ledger_utc = field_validator("reserved_at", "updated_at")(ensure_utc)

    @model_validator(mode="after")
    def _ordered(self) -> ActionLedgerEntry:
        if self.updated_at < self.reserved_at:
            raise ValueError("ledger updated_at must not precede reserved_at")
        return self
