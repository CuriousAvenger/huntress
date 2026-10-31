"""Validation, severity, reproduction, deduplication, and human-review contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import Field, field_validator, model_validator

from .base import Contract, ensure_utc
from .enums import (
    DuplicateStatus,
    GateName,
    GateStatus,
    HumanReviewStatus,
    OracleArchetype,
    SeverityBand,
    ValidationStatus,
)


class SeverityAssessment(Contract):
    """Demonstrated impact plus a deterministic scoring method.

    CVSS is optional. When evidence does not support a score, the band is
    ``UNKNOWN`` and the uncertainty is recorded rather than guessed.
    """

    band: SeverityBand
    method: str = Field(default="qualitative", max_length=40)
    cvss_vector: str | None = Field(default=None, max_length=200)
    cvss_score: Annotated[float | None, Field(ge=0.0, le=10.0)] = None
    impact_summary: str = Field(min_length=1, max_length=2000)
    exploitability_summary: str = Field(default="", max_length=2000)
    uncertainty: str = Field(default="", max_length=2000)
    scoring_inputs: dict[str, str | int | float | bool] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _cvss_consistent(self) -> SeverityAssessment:
        if (self.cvss_vector is None) != (self.cvss_score is None):
            raise ValueError("cvss_vector and cvss_score must be provided together")
        if self.cvss_score is not None:
            expected = band_for_cvss(self.cvss_score)
            if self.band is not expected:
                raise ValueError(f"band {self.band} does not match CVSS score {self.cvss_score}")
        if self.method == "cvss_v31" and self.cvss_score is None:
            raise ValueError("cvss_v31 requires a score")
        return self


def band_for_cvss(score: float) -> SeverityBand:
    """CVSS 3.1 qualitative severity ratings."""

    if score <= 0.0:
        return SeverityBand.INFO
    if score < 4.0:
        return SeverityBand.LOW
    if score < 7.0:
        return SeverityBand.MEDIUM
    if score < 9.0:
        return SeverityBand.HIGH
    return SeverityBand.CRITICAL


class GateResult(Contract):
    """One deterministic gate outcome with machine-readable reasoning."""

    gate: GateName
    status: GateStatus
    reason: str = Field(min_length=1, max_length=2000)
    evidence_refs: tuple[str, ...] = ()
    checked_at: datetime
    checker_version: str = Field(default="1.0", max_length=40)

    _checked_utc = field_validator("checked_at")(ensure_utc)

    @model_validator(mode="after")
    def _reason_shape(self) -> GateResult:
        if self.status is GateStatus.FAIL and not self.reason:
            raise ValueError("failed gates require a reason")
        return self


class ReproductionPolicyResult(Contract):
    """Whether a claim was safely and meaningfully reproduced."""

    policy_id: str = Field(min_length=1, max_length=120)
    required_repetitions: int = Field(default=1, ge=0, le=10)
    performed_repetitions: int = Field(default=0, ge=0, le=10)
    status: GateStatus
    reason: str = Field(min_length=1, max_length=2000)
    side_effect_class: str = Field(min_length=1, max_length=40)

    @model_validator(mode="after")
    def _counts(self) -> ReproductionPolicyResult:
        if self.performed_repetitions > self.required_repetitions:
            raise ValueError("performed repetitions exceed required repetitions")
        if self.status is GateStatus.PASS and self.performed_repetitions < self.required_repetitions:
            raise ValueError("passing reproduction requires the required repetitions")
        return self


class DedupResult(Contract):
    """Exact and similarity-based duplicate assessment."""

    status: DuplicateStatus
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    duplicate_of: str | None = Field(default=None, pattern=r"^vf_[a-zA-Z0-9_-]{6,80}$")
    similarity: Annotated[float, Field(ge=0.0, le=1.0)] = 0.0
    reason: str = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def _duplicate_shape(self) -> DedupResult:
        if self.status is DuplicateStatus.DUPLICATE and not self.duplicate_of:
            raise ValueError("duplicate status requires duplicate_of")
        if self.status is DuplicateStatus.UNIQUE and self.duplicate_of is not None:
            raise ValueError("unique status must not carry duplicate_of")
        return self


class ValidatedFinding(Contract):
    """A claim that passed the deterministic gate pipeline.

    This is the only object the reporting layer may turn into a report draft.
    A ``ValidatedFinding`` does not imply human approval or submission.
    """

    finding_id: str = Field(pattern=r"^vf_[a-zA-Z0-9_-]{6,80}$")
    engagement_id: str = Field(pattern=r"^eng_[a-zA-Z0-9_-]{6,80}$")
    hypothesis_id: str | None = Field(default=None, pattern=r"^hyp_[a-zA-Z0-9_-]{6,80}$")
    tool_finding_ids: tuple[str, ...] = Field(min_length=1)
    target_id: str = Field(pattern=r"^tgt_[a-zA-Z0-9_-]{6,80}$")
    bug_class_id: str = Field(pattern=r"^bug_[a-z0-9_]{2,60}$")
    oracle_archetype: OracleArchetype
    title: str = Field(min_length=1, max_length=300)
    claim: str = Field(min_length=10, max_length=4000)
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    gates: tuple[GateResult, ...] = Field(min_length=1)
    reproduction: ReproductionPolicyResult
    severity: SeverityAssessment
    dedup: DedupResult
    status: ValidationStatus
    validated_at: datetime
    validator_version: str = Field(default="1.0", max_length=40)
    human_review_status: HumanReviewStatus = HumanReviewStatus.PENDING
    reviewer: str | None = Field(default=None, max_length=200)
    reviewed_at: datetime | None = None
    review_notes: str = Field(default="", max_length=4000)

    _validated_utc = field_validator("validated_at")(ensure_utc)

    @field_validator("reviewed_at")
    @classmethod
    def _reviewed_utc(cls, value: datetime | None) -> datetime | None:
        return ensure_utc(value) if value is not None else None

    @model_validator(mode="after")
    def _gate_consistency(self) -> ValidatedFinding:
        by_gate = {g.gate: g.status for g in self.gates}
        if len(by_gate) != len(self.gates):
            raise ValueError("each gate may appear at most once")
        required = {
            GateName.SCOPE_RECHECK,
            GateName.EVIDENCE_COMPLETENESS,
            GateName.REPRODUCIBILITY,
            GateName.TECHNICAL_ORACLE,
            GateName.SEVERITY,
            GateName.DEDUPLICATION,
        }
        missing = required - set(by_gate)
        if missing:
            raise ValueError(f"missing required gates: {sorted(missing)}")
        if self.status is ValidationStatus.PASSED:
            bad = [g.gate for g in self.gates if g.status in {GateStatus.FAIL, GateStatus.INCONCLUSIVE}]
            if bad:
                raise ValueError(f"passed finding has failing/inconclusive gates: {bad}")
            if self.dedup.status is DuplicateStatus.DUPLICATE:
                raise ValueError("a duplicate cannot be a passed finding")
            if self.reproduction.status is not GateStatus.PASS:
                raise ValueError("a passed finding requires a passing reproduction policy")
        if self.status is ValidationStatus.FAILED and not any(
            g.status is GateStatus.FAIL for g in self.gates
        ):
            raise ValueError("failed finding requires at least one failed gate")
        if self.human_review_status is HumanReviewStatus.APPROVED and not self.reviewer:
            raise ValueError("approved review requires a reviewer")
        return self


class HumanReviewRecord(Contract):
    """Durable reviewer decision. Rejection never becomes a confirmed finding."""

    review_id: str = Field(pattern=r"^rev_[a-zA-Z0-9_-]{6,80}$")
    engagement_id: str = Field(pattern=r"^eng_[a-zA-Z0-9_-]{6,80}$")
    finding_id: str = Field(pattern=r"^vf_[a-zA-Z0-9_-]{6,80}$")
    reviewer: str = Field(min_length=1, max_length=200)
    decision: HumanReviewStatus
    notes: str = Field(default="", max_length=4000)
    reviewed_at: datetime
    evidence_refs: tuple[str, ...] = ()

    _reviewed_utc = field_validator("reviewed_at")(ensure_utc)

    @model_validator(mode="after")
    def _decision_shape(self) -> HumanReviewRecord:
        if self.decision not in {
            HumanReviewStatus.APPROVED,
            HumanReviewStatus.REJECTED,
            HumanReviewStatus.NEEDS_MORE_EVIDENCE,
        }:
            raise ValueError("review decision must be approved, rejected, or needs_more_evidence")
        return self
