"""Knowledge ingestion and tenant-scoped retrieval.

The service binds every read and write to an explicit tenant. The persistence
layer already filters ``global`` plus the requesting tenant, but this layer
re-checks the boundary so a caller cannot widen a query by editing a contract
field. Knowledge never grants authority; it only informs a hypothesis.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from datetime import datetime, timedelta
from typing import Protocol

from huntress_contracts import (
    Actor,
    ActorType,
    AuditEvent,
    KnowledgeUnit,
    RetrievalQuery,
    RetrievedKnowledge,
    ensure_utc,
    new_id,
    utc_now,
)

from .errors import KnowledgeAccessDenied, KnowledgeConflict, KnowledgeIntegrityError
from .hashing import knowledge_content_hash
from .seeds import seed_units

logger = logging.getLogger(__name__)

GLOBAL_TENANT = "global"


class KnowledgeStore(Protocol):
    """Persistence port implemented by ``KnowledgeRepository``."""

    def upsert(self, unit: KnowledgeUnit) -> KnowledgeUnit: ...

    def get(self, unit_id: str) -> KnowledgeUnit | None: ...

    def search(self, query: RetrievalQuery) -> list[RetrievedKnowledge]: ...

    def count(self) -> int: ...


class AuditSink(Protocol):
    def append(self, event: AuditEvent) -> AuditEvent: ...


class KnowledgeService:
    """Ingest reviewed corpus entries and retrieve only permitted tenants."""

    def __init__(
        self,
        *,
        repository: KnowledgeStore,
        max_age_days: int = 365,
        audit: AuditSink | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        if max_age_days < 1:
            raise ValueError("max_age_days must be positive")
        self._repository = repository
        self._max_age_days = max_age_days
        self._audit = audit
        self._clock = clock

    def ingest(
        self,
        unit: KnowledgeUnit,
        *,
        expected_tenant: str | None = None,
    ) -> KnowledgeUnit:
        """Validate and persist one unit.

        ``expected_tenant`` is the caller's authorization context. A caller may
        write to its own tenant or to ``global``; it may never write into a
        different tenant. Existing identifiers cannot change tenant.
        """

        self._check_tenant(unit.tenant_scope, expected_tenant)
        actual = knowledge_content_hash(unit)
        if actual != unit.content_hash:
            raise KnowledgeIntegrityError(
                f"knowledge unit {unit.unit_id} content hash does not match its content"
            )

        existing = self._repository.get(unit.unit_id)
        if existing is not None and existing.tenant_scope != unit.tenant_scope:
            raise KnowledgeConflict(
                f"knowledge unit {unit.unit_id} belongs to tenant {existing.tenant_scope!r}"
            )
        if existing is not None and existing.content_hash == unit.content_hash:
            return existing

        if unit.supersedes is not None:
            target = self._repository.get(unit.supersedes)
            if target is None:
                raise KnowledgeConflict(f"superseded unit {unit.supersedes} does not exist")
            if target.tenant_scope != unit.tenant_scope:
                raise KnowledgeConflict("a unit may only supersede a unit in the same tenant")
            if target.unit_id == unit.unit_id:
                raise KnowledgeConflict("a unit may not supersede itself")

        try:
            stored = self._repository.upsert(unit)
        except Exception as exc:
            logger.exception("failed to persist knowledge unit %s", unit.unit_id)
            raise KnowledgeIntegrityError(f"failed to persist knowledge unit: {exc}") from exc

        self._audit_ingest(unit, created=existing is None)
        return stored

    def ingest_many(
        self,
        units: Iterable[KnowledgeUnit],
        *,
        expected_tenant: str | None = None,
    ) -> tuple[KnowledgeUnit, ...]:
        return tuple(self.ingest(unit, expected_tenant=expected_tenant) for unit in units)

    def install_seeds(self) -> tuple[KnowledgeUnit, ...]:
        """Idempotently install the reviewed global seed corpus."""

        return self.ingest_many(seed_units(), expected_tenant=GLOBAL_TENANT)

    def retrieve(
        self,
        query: RetrievalQuery,
        *,
        tenant_scope: str,
        allow_stale: bool = False,
    ) -> tuple[RetrievedKnowledge, ...]:
        """Retrieve global plus one tenant's units, with a freshness floor."""

        self._check_tenant(query.tenant_scope, tenant_scope)
        fresh_after = query.require_fresh_after
        if fresh_after is None and not allow_stale:
            fresh_after = self._moment() - timedelta(days=self._max_age_days)
        bound = query.model_copy(update={"require_fresh_after": fresh_after})
        results = tuple(self._repository.search(bound))
        allowed = {GLOBAL_TENANT, tenant_scope}
        if any(result.unit.tenant_scope not in allowed for result in results):
            raise KnowledgeAccessDenied("retrieval returned a unit from an unauthorized tenant")
        return results

    def get(self, unit_id: str, *, tenant_scope: str) -> KnowledgeUnit | None:
        unit = self._repository.get(unit_id)
        if unit is None:
            return None
        if unit.tenant_scope not in {GLOBAL_TENANT, tenant_scope}:
            raise KnowledgeAccessDenied(
                f"knowledge unit {unit_id} belongs to an unauthorized tenant"
            )
        return unit

    def count(self) -> int:
        return self._repository.count()

    def is_fresh(self, unit: KnowledgeUnit, *, now: datetime | None = None) -> bool:
        moment = ensure_utc(now) if now is not None else self._moment()
        return unit.freshness_at >= moment - timedelta(days=self._max_age_days)

    @staticmethod
    def _check_tenant(tenant_scope: str, authorized: str | None) -> None:
        if not tenant_scope.strip():
            raise KnowledgeAccessDenied("tenant scope must not be empty")
        if authorized is not None and tenant_scope not in {GLOBAL_TENANT, authorized}:
            raise KnowledgeAccessDenied(
                f"tenant {tenant_scope!r} is outside the authorized scope {authorized!r}"
            )

    def _audit_ingest(self, unit: KnowledgeUnit, *, created: bool) -> None:
        if self._audit is None:
            return
        engagement_id = unit.tenant_scope if unit.tenant_scope.startswith("eng_") else None
        event = AuditEvent(
            event_id=new_id("aud"),
            occurred_at=self._moment(),
            engagement_id=engagement_id,
            actor=Actor(type=ActorType.SYSTEM, id="knowledge-service"),
            action="knowledge_ingest",
            outcome="created" if created else "updated",
            correlation_id=unit.unit_id,
            details={
                "tenant_scope": unit.tenant_scope[:120],
                "tier": unit.tier.value,
                "title": unit.title[:200],
                "cwe_count": len(unit.cwe_ids),
                "oracle_count": len(unit.oracle_archetypes),
                "content_hash": unit.content_hash,
            },
        )
        self._audit.append(event)

    def _moment(self) -> datetime:
        return ensure_utc(self._clock())
