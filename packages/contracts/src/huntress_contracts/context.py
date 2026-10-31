"""Context-packet contracts for bounded, fresh model invocations.

A packet is compiled from durable state for one task. Chat history is never the
source of truth. Target-controlled text is isolated in sections marked
``untrusted=True`` and fenced by the renderer in the reasoning package.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import Field, field_validator, model_validator

from .base import Contract, ensure_utc
from .enums import ContextTask, FindingConfidence
from .policy import BudgetSnapshot


class ContextSectionKind(StrEnum):
    INSTRUCTIONS = "instructions"
    AUTHORIZATION = "authorization"
    TARGET_BRIEF = "target_brief"
    OBJECTIVE = "objective"
    EVIDENCE = "evidence"
    KNOWLEDGE = "knowledge"
    WORKING_MEMORY = "working_memory"
    BUDGET = "budget"
    OUTPUT_CONTRACT = "output_contract"


class EvidenceDigestItem(Contract):
    """A bounded observation excerpt, explicitly untrusted."""

    finding_id: str = Field(min_length=1, max_length=80)
    target_id: str = Field(min_length=1, max_length=80)
    finding_type: str = Field(min_length=1, max_length=120)
    confidence: FindingConfidence
    artifact_refs: tuple[str, ...] = ()
    excerpt: str = Field(default="", max_length=4000)
    untrusted: bool = True


class ContextSection(Contract):
    """One ordered section of the context packet."""

    kind: ContextSectionKind
    title: str = Field(min_length=1, max_length=200)
    content: str = Field(min_length=0, max_length=60_000)
    untrusted: bool = False
    artifact_refs: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _untrusted_has_refs(self) -> ContextSection:
        if self.untrusted and not self.artifact_refs:
            raise ValueError("untrusted sections must reference preserved artifacts")
        return self


class ContextPacket(Contract):
    """A versioned, hash-addressed prompt context for exactly one model call."""

    packet_id: str = Field(pattern=r"^ctx_[a-zA-Z0-9_-]{6,80}$")
    engagement_id: str = Field(pattern=r"^eng_[a-zA-Z0-9_-]{6,80}$")
    task: ContextTask
    generated_at: datetime
    policy_version: str = Field(min_length=1, max_length=80)
    scope_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    sections: tuple[ContextSection, ...] = Field(min_length=1)
    allowed_target_ids: tuple[str, ...] = ()
    allowed_profile_ids: tuple[str, ...] = ()
    allowed_hypothesis_ids: tuple[str, ...] = ()
    allowed_evidence_ids: tuple[str, ...] = ()
    budget_snapshot: BudgetSnapshot
    prompt_version: str = Field(min_length=1, max_length=80)
    context_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    approx_tokens: int = Field(default=0, ge=0)
    untrusted_content_present: bool = False

    _generated_utc = field_validator("generated_at")(ensure_utc)

    @model_validator(mode="after")
    def _ordered(self) -> ContextPacket:
        kinds = [s.kind for s in self.sections]
        if len(kinds) != len(set(kinds)):
            raise ValueError("context sections must be unique by kind")
        if kinds[0] is not ContextSectionKind.INSTRUCTIONS:
            raise ValueError("instructions must be the first section")
        if kinds[-1] is not ContextSectionKind.OUTPUT_CONTRACT:
            raise ValueError("output contract must be the last section")
        for values in (
            self.allowed_target_ids,
            self.allowed_profile_ids,
            self.allowed_hypothesis_ids,
            self.allowed_evidence_ids,
        ):
            if len(values) != len(set(values)):
                raise ValueError("allowed id lists must be unique")
        if self.untrusted_content_present != any(s.untrusted for s in self.sections):
            raise ValueError("untrusted_content_present must reflect section flags")
        return self
