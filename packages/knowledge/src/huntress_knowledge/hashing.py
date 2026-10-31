"""Deterministic knowledge-unit hashing and construction."""

from __future__ import annotations

from datetime import datetime

from huntress_contracts import (
    KnowledgeSource,
    KnowledgeTier,
    KnowledgeUnit,
    OracleArchetype,
    VulnerabilityDomain,
    model_self_hash,
)

_PLACEHOLDER_HASH = "0" * 64


def knowledge_content_hash(unit: KnowledgeUnit) -> str:
    """Hash every field except ``content_hash`` itself."""

    return model_self_hash(unit, exclude=frozenset({"content_hash"}))


def make_knowledge_unit(
    *,
    unit_id: str,
    tier: KnowledgeTier,
    title: str,
    summary: str,
    source: KnowledgeSource,
    freshness_at: datetime,
    created_at: datetime,
    tenant_scope: str = "global",
    body_ref: str | None = None,
    tags: tuple[str, ...] = (),
    cwe_ids: tuple[int, ...] = (),
    domain: VulnerabilityDomain | None = None,
    component: str | None = None,
    version_range: str | None = None,
    oracle_archetypes: tuple[OracleArchetype, ...] = (),
    supersedes: str | None = None,
) -> KnowledgeUnit:
    """Build a unit with a correctly sealed ``content_hash``."""

    unit = KnowledgeUnit(
        unit_id=unit_id,
        tenant_scope=tenant_scope,
        tier=tier,
        title=title,
        summary=summary,
        body_ref=body_ref,
        tags=tags,
        cwe_ids=cwe_ids,
        domain=domain,
        component=component,
        version_range=version_range,
        oracle_archetypes=oracle_archetypes,
        source=source,
        freshness_at=freshness_at,
        created_at=created_at,
        content_hash=_PLACEHOLDER_HASH,
        supersedes=supersedes,
    )
    sealed = unit.model_copy(update={"content_hash": knowledge_content_hash(unit)})
    return KnowledgeUnit.model_validate(sealed.model_dump(mode="python"))
