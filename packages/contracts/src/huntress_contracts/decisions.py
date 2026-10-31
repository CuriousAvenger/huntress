"""Typed investigation decisions proposed by the reasoning layer.

The closed action enum and the absence of any free-form command, URL, budget,
or scope field are the primary defence against a compromised or prompt-injected
model. ``DecisionValidator`` (reasoning package) additionally verifies that every
referenced ID exists in the supplied context.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import Field, field_validator, model_validator

from .base import Contract, ensure_utc
from .enums import ActionKind, DecisionSource
from .findings import ModelAttribution


class InvestigationDecision(Contract):
    """One bounded next step chosen from a closed action vocabulary."""

    decision_id: str = Field(pattern=r"^dec_[a-zA-Z0-9_-]{6,80}$")
    engagement_id: str = Field(pattern=r"^eng_[a-zA-Z0-9_-]{6,80}$")
    action: ActionKind
    target_id: str | None = Field(default=None, pattern=r"^tgt_[a-zA-Z0-9_-]{6,80}$")
    profile_id: str | None = Field(default=None, max_length=120)
    hypothesis_id: str | None = Field(default=None, pattern=r"^hyp_[a-zA-Z0-9_-]{6,80}$")
    evidence_ids: tuple[str, ...] = ()
    rationale_summary: str = Field(min_length=1, max_length=2000)
    confidence: Annotated[float, Field(ge=0.0, le=1.0)] = 0.0
    source: DecisionSource = DecisionSource.MODEL
    created_at: datetime
    expires_at: datetime | None = None
    model_attribution: ModelAttribution | None = None

    @field_validator("created_at")
    @classmethod
    def _created_utc(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    @field_validator("expires_at")
    @classmethod
    def _expires_utc(cls, value: datetime | None) -> datetime | None:
        return ensure_utc(value) if value is not None else None

    @model_validator(mode="after")
    def _action_contract(self) -> InvestigationDecision:
        if self.action is ActionKind.RUN_APPROVED_PROFILE:
            if not self.target_id or not self.profile_id:
                raise ValueError("run_approved_profile requires target_id and profile_id")
        elif self.action is ActionKind.REVIEW_EVIDENCE:
            if not self.evidence_ids:
                raise ValueError("review_evidence requires at least one evidence id")
        elif self.action is ActionKind.REQUEST_HUMAN_REVIEW:
            if not self.hypothesis_id and not self.evidence_ids:
                raise ValueError("request_human_review requires a hypothesis or evidence")
        elif self.action is ActionKind.STOP and self.profile_id is not None:
            raise ValueError("stop must not reference a profile")
        if self.action is not ActionKind.RUN_APPROVED_PROFILE and self.profile_id is not None:
            raise ValueError(f"{self.action} must not reference a profile")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("evidence_ids must be unique")
        if self.expires_at is not None and self.expires_at <= self.created_at:
            raise ValueError("decision expires_at must be after created_at")
        return self


class DecisionValidation(Contract):
    """Deterministic verdict on a proposed decision, before policy evaluation."""

    decision_id: str = Field(pattern=r"^dec_[a-zA-Z0-9_-]{6,80}$")
    valid: bool
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    checked_at: datetime

    _checked_utc = field_validator("checked_at")(ensure_utc)

    @model_validator(mode="after")
    def _errors_consistent(self) -> DecisionValidation:
        if self.valid and self.errors:
            raise ValueError("a valid decision cannot carry errors")
        if not self.valid and not self.errors:
            raise ValueError("an invalid decision must carry at least one error")
        return self
