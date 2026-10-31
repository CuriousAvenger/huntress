"""Versioned knowledge-corpus contracts.

Retrieval is a hypothesis-generation aid. A knowledge unit can explain a
technique or a false-positive pattern; it can never authorize an action or
decide that a validator passed.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, field_validator, model_validator

from .base import Contract, ensure_utc
from .enums import KnowledgeTier, OracleArchetype, VulnerabilityDomain


class KnowledgeSource(Contract):
    """Provenance for an ingested corpus entry."""

    uri: str = Field(min_length=1, max_length=1024)
    publisher: str = Field(min_length=1, max_length=200)
    fetched_at: datetime
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    license: str = Field(default="unknown", max_length=120)
    trust_tier: str = Field(default="community", max_length=40)

    _fetched_utc = field_validator("fetched_at")(ensure_utc)


class KnowledgeUnit(Contract):
    """A small, tagged, versioned corpus entry with tenant isolation."""

    unit_id: str = Field(pattern=r"^ku_[a-zA-Z0-9_-]{6,80}$")
    tenant_scope: str = Field(
        default="global",
        max_length=120,
        description="'global' or a program/engagement id; never cross-read",
    )
    tier: KnowledgeTier
    title: str = Field(min_length=1, max_length=300)
    summary: str = Field(min_length=1, max_length=4000)
    body_ref: str | None = Field(default=None, max_length=128)
    tags: tuple[str, ...] = ()
    cwe_ids: tuple[int, ...] = ()
    domain: VulnerabilityDomain | None = None
    component: str | None = Field(default=None, max_length=200)
    version_range: str | None = Field(default=None, max_length=200)
    oracle_archetypes: tuple[OracleArchetype, ...] = ()
    source: KnowledgeSource
    freshness_at: datetime
    created_at: datetime
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    supersedes: str | None = Field(default=None, pattern=r"^ku_[a-zA-Z0-9_-]{6,80}$")

    _knowledge_utc = field_validator("freshness_at", "created_at")(ensure_utc)

    @model_validator(mode="after")
    def _tenant(self) -> KnowledgeUnit:
        if self.tenant_scope.strip() == "":
            raise ValueError("tenant_scope must not be empty")
        return self


class RetrievalQuery(Contract):
    """Metadata filters first, then lexical ranking."""

    tenant_scope: str = Field(default="global", max_length=120)
    text: str = Field(default="", max_length=2000)
    cwe_ids: tuple[int, ...] = ()
    domain: VulnerabilityDomain | None = None
    component: str | None = Field(default=None, max_length=200)
    oracle_archetypes: tuple[OracleArchetype, ...] = ()
    tiers: tuple[KnowledgeTier, ...] = ()
    limit: int = Field(default=5, ge=1, le=50)
    require_fresh_after: datetime | None = None

    @field_validator("require_fresh_after")
    @classmethod
    def _fresh_utc(cls, value: datetime | None) -> datetime | None:
        return ensure_utc(value) if value is not None else None


class RetrievedKnowledge(Contract):
    unit: KnowledgeUnit
    score: float = Field(ge=0.0)
    reason: str = Field(default="metadata+lexical", max_length=200)
