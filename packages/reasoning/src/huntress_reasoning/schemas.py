"""Model-facing structured-output schemas.

The model never sees or supplies server-owned identifiers, timestamps, oracle
selection, or authority fields. It fills a draft; the service assigns those
fields and validates every reference against the context packet.
"""

from __future__ import annotations

import json
from typing import Annotated

from huntress_contracts import ActionKind, ContextTask
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Draft(BaseModel):
    """Strict base for every model-produced draft."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        validate_default=True,
    )


class DecisionDraft(Draft):
    """A bounded next action proposal; IDs are resolved server-side."""

    action: ActionKind
    target_id: str | None = Field(default=None, max_length=80)
    profile_id: str | None = Field(default=None, max_length=120)
    hypothesis_id: str | None = Field(default=None, max_length=80)
    evidence_ids: tuple[str, ...] = ()
    rationale_summary: str = Field(min_length=1, max_length=2000)
    confidence: Annotated[float, Field(ge=0.0, le=1.0)] = 0.0

    @field_validator("target_id", "profile_id", "hypothesis_id", mode="before")
    @classmethod
    def _blank_optional_id(cls, value: object) -> object:
        """Treat blank optional IDs from a model as absent, not malformed."""

        if isinstance(value, str) and not value.strip():
            return None
        return value

    @model_validator(mode="after")
    def _action_shape(self) -> DecisionDraft:
        if self.action is ActionKind.RUN_APPROVED_PROFILE:
            if not self.target_id or not self.profile_id:
                raise ValueError("run_approved_profile requires target_id and profile_id")
        elif self.profile_id is not None:
            raise ValueError(f"{self.action} must not reference a profile")
        if self.action is ActionKind.REVIEW_EVIDENCE and not self.evidence_ids:
            raise ValueError("review_evidence requires at least one evidence id")
        if self.action is ActionKind.REQUEST_HUMAN_REVIEW and not (self.hypothesis_id or self.evidence_ids):
            raise ValueError("request_human_review requires a hypothesis or evidence")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("evidence_ids must be unique")
        return self


class HypothesisDraft(Draft):
    """A falsifiable hypothesis; the oracle is assigned from the bug class."""

    bug_class_id: str = Field(pattern=r"^bug_[a-z0-9_]{2,60}$")
    target_id: str = Field(pattern=r"^tgt_[a-zA-Z0-9_-]{6,80}$")
    claim: str = Field(min_length=10, max_length=2000)
    falsification_test: str = Field(min_length=10, max_length=2000)
    rationale_summary: str = Field(min_length=1, max_length=4000)
    evidence_ids: tuple[str, ...] = Field(min_length=1)
    confidence: Annotated[float, Field(ge=0.0, le=1.0)] = 0.0
    suggested_profile_ids: tuple[str, ...] = ()

    @field_validator("evidence_ids", "suggested_profile_ids")
    @classmethod
    def _unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("identifier lists must be unique")
        return value


class FailureReflectionDraft(Draft):
    """Structured reflection after a failed test or validation."""

    summary: str = Field(min_length=10, max_length=4000)
    likely_gaps: tuple[str, ...] = Field(min_length=1, max_length=10)
    discriminating_evidence: tuple[str, ...] = Field(default=(), max_length=10)
    next_step: str = Field(default="", max_length=1000)
    avoid_blind_retry: bool = True

    @field_validator("likely_gaps", "discriminating_evidence")
    @classmethod
    def _bounded_items(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(len(item) > 500 for item in value):
            raise ValueError("reflection items may not exceed 500 characters")
        return value


class ImpactNarrativeDraft(Draft):
    """Draft impact language tied to demonstrated facts only."""

    summary: str = Field(min_length=10, max_length=2000)
    demonstrated_impact: str = Field(min_length=10, max_length=4000)
    uncertainty: str = Field(default="", max_length=2000)
    severity_rationale: str = Field(default="", max_length=2000)
    evidence_ids: tuple[str, ...] = ()

    @field_validator("evidence_ids")
    @classmethod
    def _unique_evidence(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("evidence_ids must be unique")
        return value


DRAFT_MODELS: dict[ContextTask, type[Draft]] = {
    ContextTask.ACTION_SELECTION: DecisionDraft,
    ContextTask.HYPOTHESIS_SYNTHESIS: HypothesisDraft,
    ContextTask.FAILURE_REFLECTION: FailureReflectionDraft,
    ContextTask.IMPACT_NARRATIVE: ImpactNarrativeDraft,
}


def draft_model_for(task: ContextTask) -> type[Draft] | None:
    return DRAFT_MODELS.get(task)


def output_contract(task: ContextTask) -> str:
    """Return the exact JSON schema and non-negotiable output rules."""

    model = DRAFT_MODELS.get(task)
    if model is None:
        raise ValueError(f"no structured output schema for task {task.value}")
    schema = json.dumps(model.model_json_schema(), indent=2, sort_keys=True)
    return (
        "Return exactly one JSON object matching this schema. Do not add fields, "
        "Markdown fences, prose outside the object, URLs, shell commands, budgets, "
        "or scope changes. Only reference IDs listed in the authorization and "
        "allowed-ID sections.\n\n"
        f"Schema name: {model.__name__}\n{schema}"
    )
