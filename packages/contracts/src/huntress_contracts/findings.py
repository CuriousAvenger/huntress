"""Discovery observations and structured hypotheses.

A ``ToolFinding`` is an observation, not a vulnerability. It may only become a
``ValidatedFinding`` after the verification pipeline succeeds.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import Field, field_validator, model_validator

from .base import Contract, ensure_utc
from .enums import (
    FindingConfidence,
    HypothesisStatus,
    OracleArchetype,
    ScanWorkstream,
    ToolRunStatus,
    VulnerabilityDomain,
)


class BugClass(Contract):
    """Canonical CWE vocabulary with an explicit proof-oracle mapping.

    The vulnerability domain and the proof oracle are deliberately separate:
    two web bugs can require completely different evidence patterns.
    """

    bug_class_id: str = Field(pattern=r"^bug_[a-z0-9_]{2,60}$")
    cwe_id: int = Field(ge=1, le=2000)
    name: str = Field(min_length=1, max_length=200)
    domain: VulnerabilityDomain
    oracle_archetype: OracleArchetype
    description: str = Field(min_length=1, max_length=2000)
    default_severity_hint: str = Field(default="unknown", max_length=40)
    tags: tuple[str, ...] = ()


class ToolFinding(Contract):
    """One normalized scanner observation with complete provenance."""

    finding_id: str = Field(pattern=r"^tf_[a-zA-Z0-9_-]{6,80}$")
    engagement_id: str = Field(pattern=r"^eng_[a-zA-Z0-9_-]{6,80}$")
    target_id: str = Field(pattern=r"^tgt_[a-zA-Z0-9_-]{6,80}$")
    tool_profile_id: str = Field(min_length=1, max_length=120)
    tool_version: str = Field(min_length=1, max_length=80)
    parser_version: str = Field(default="1.0", max_length=40)
    workstream: ScanWorkstream
    finding_type: str = Field(min_length=1, max_length=120)
    title: str = Field(min_length=1, max_length=300)
    bug_class_id: str | None = Field(default=None, pattern=r"^bug_[a-z0-9_]{2,60}$")
    cwe_ids: tuple[int, ...] = ()
    signature_ref: str | None = Field(default=None, max_length=200)
    confidence: FindingConfidence
    oracle_hint: OracleArchetype | None = None
    artifact_refs: tuple[str, ...] = Field(min_length=1)
    observed_at: datetime
    excerpt: str = Field(default="", max_length=4000, description="Bounded, untrusted target excerpt")
    details: dict[str, str | int | float | bool] = Field(default_factory=dict)
    evidence_fingerprint: str = Field(default="", max_length=128)

    _observed_utc = field_validator("observed_at")(ensure_utc)

    @model_validator(mode="after")
    def _details_bounded(self) -> ToolFinding:
        if len(self.details) > 40:
            raise ValueError("tool finding details may not exceed 40 keys")
        for key, value in self.details.items():
            if len(key) > 80:
                raise ValueError("detail key too long")
            if isinstance(value, str) and len(value) > 2000:
                raise ValueError("detail string too long")
        return self


class ProfileRunSummary(Contract):
    """Per-profile result inside a sweep digest."""

    profile_id: str = Field(min_length=1, max_length=120)
    profile_version: str = Field(min_length=1, max_length=40)
    target_id: str = Field(pattern=r"^tgt_[a-zA-Z0-9_-]{6,80}$")
    status: ToolRunStatus
    findings: int = Field(ge=0)
    duration_ms: int = Field(ge=0)
    attempts: int = Field(default=1, ge=0)
    error_code: str | None = Field(default=None, max_length=80)
    artifact_refs: tuple[str, ...] = ()


class ToolSweepDigest(Contract):
    """Engagement-level coverage summary with references to omitted raw output."""

    sweep_id: str = Field(pattern=r"^sweep_[a-zA-Z0-9_-]{6,80}$")
    engagement_id: str = Field(pattern=r"^eng_[a-zA-Z0-9_-]{6,80}$")
    started_at: datetime
    finished_at: datetime
    status: ToolRunStatus
    scope_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    profiles_run: tuple[ProfileRunSummary, ...] = ()
    total_findings: int = Field(default=0, ge=0)
    finding_counts: dict[str, int] = Field(default_factory=dict)
    artifact_refs: tuple[str, ...] = ()
    notes: str = Field(default="", max_length=2000)

    _sweep_utc = field_validator("started_at", "finished_at")(ensure_utc)

    @model_validator(mode="after")
    def _ordered(self) -> ToolSweepDigest:
        if self.finished_at < self.started_at:
            raise ValueError("sweep finished_at must not precede started_at")
        return self


class ModelAttribution(Contract):
    """Non-secret metadata linking a structured output to a model call."""

    call_id: str = Field(pattern=r"^mc_[a-zA-Z0-9_-]{6,80}$")
    provider: str = Field(min_length=1, max_length=80)
    model_id: str = Field(min_length=1, max_length=200)
    prompt_version: str = Field(min_length=1, max_length=80)
    context_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class VulnerabilityHypothesis(Contract):
    """A falsifiable claim, never proof. Confidence is a routing aid only."""

    hypothesis_id: str = Field(pattern=r"^hyp_[a-zA-Z0-9_-]{6,80}$")
    engagement_id: str = Field(pattern=r"^eng_[a-zA-Z0-9_-]{6,80}$")
    target_id: str = Field(pattern=r"^tgt_[a-zA-Z0-9_-]{6,80}$")
    bug_class_id: str = Field(pattern=r"^bug_[a-z0-9_]{2,60}$")
    oracle_archetype: OracleArchetype
    claim: str = Field(min_length=10, max_length=2000)
    falsification_test: str = Field(min_length=10, max_length=2000)
    rationale_summary: str = Field(min_length=1, max_length=4000)
    evidence_ids: tuple[str, ...] = Field(min_length=1)
    confidence: Annotated[float, Field(ge=0.0, le=1.0)] = 0.0
    suggested_profile_ids: tuple[str, ...] = ()
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    created_at: datetime
    model_attribution: ModelAttribution | None = None

    _created_utc = field_validator("created_at")(ensure_utc)

    @model_validator(mode="after")
    def _evidence_unique(self) -> VulnerabilityHypothesis:
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("hypothesis evidence_ids must be unique")
        return self
