"""Tenant-bound knowledge ingestion, supersession, and freshness."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from huntress_contracts import KnowledgeTier, RetrievalQuery, utc_now
from huntress_knowledge import (
    KnowledgeAccessDenied,
    KnowledgeConflict,
    KnowledgeIntegrityError,
    KnowledgeService,
    knowledge_content_hash,
)
from huntress_persistence import Database, RepositoryBundle
from tests.helpers import make_knowledge


@pytest.fixture
def service(tmp_path: Path) -> KnowledgeService:
    database = Database(tmp_path / "knowledge.db")
    database.migrate()
    return KnowledgeService(repository=RepositoryBundle(database).knowledge)


def test_seed_corpus_installs_idempotently(service: KnowledgeService) -> None:
    first = service.install_seeds()
    second = service.install_seeds()
    assert len(first) == 12
    assert len(second) == 12
    assert service.count() == 12
    assert all(unit.tenant_scope == "global" for unit in first)


def test_tenant_units_are_only_visible_to_their_tenant(service: KnowledgeService) -> None:
    engagement_a = "eng_tenanta00001"
    engagement_b = "eng_tenantb00001"
    global_unit = make_knowledge(unit_id="ku_global000001", title="Global quasar note")
    tenant_unit = make_knowledge(
        unit_id="ku_tenanta00001",
        tenant_scope=engagement_a,
        title="Tenant quasar note",
    )
    service.ingest(global_unit, expected_tenant=engagement_a)
    service.ingest(tenant_unit, expected_tenant=engagement_a)

    results = service.retrieve(
        RetrievalQuery(tenant_scope=engagement_a, text="quasar"),
        tenant_scope=engagement_a,
    )
    assert {result.unit.unit_id for result in results} == {
        global_unit.unit_id,
        tenant_unit.unit_id,
    }

    other = service.retrieve(
        RetrievalQuery(tenant_scope=engagement_b, text="quasar"),
        tenant_scope=engagement_b,
    )
    assert {result.unit.unit_id for result in other} == {global_unit.unit_id}

    with pytest.raises(KnowledgeAccessDenied):
        service.retrieve(RetrievalQuery(tenant_scope=engagement_a), tenant_scope=engagement_b)
    with pytest.raises(KnowledgeAccessDenied):
        service.get(tenant_unit.unit_id, tenant_scope=engagement_b)


def test_ingestion_cannot_write_into_another_tenant(service: KnowledgeService) -> None:
    unit = make_knowledge(tenant_scope="eng_tenanta00001")
    with pytest.raises(KnowledgeAccessDenied):
        service.ingest(unit, expected_tenant="eng_tenantb00001")


def test_content_hash_mismatch_is_rejected(service: KnowledgeService) -> None:
    unit = make_knowledge()
    tampered = unit.model_copy(update={"summary": "changed after sealing"})
    assert knowledge_content_hash(tampered) != tampered.content_hash
    with pytest.raises(KnowledgeIntegrityError):
        service.ingest(tampered)


def test_existing_unit_cannot_change_tenant(service: KnowledgeService) -> None:
    original = make_knowledge(unit_id="ku_shared000001", tenant_scope="eng_tenanta00001")
    service.ingest(original, expected_tenant="eng_tenanta00001")
    changed = make_knowledge(unit_id="ku_shared000001", tenant_scope="eng_tenantb00001")
    with pytest.raises(KnowledgeConflict, match="belongs to tenant"):
        service.ingest(changed, expected_tenant="eng_tenantb00001")


def test_supersession_must_stay_in_the_same_tenant(service: KnowledgeService) -> None:
    original = make_knowledge(unit_id="ku_original0001", tenant_scope="eng_tenanta00001")
    service.ingest(original, expected_tenant="eng_tenanta00001")

    missing = make_knowledge(
        unit_id="ku_revision0001",
        tenant_scope="eng_tenanta00001",
        supersedes="ku_missing000001",
    )
    with pytest.raises(KnowledgeConflict, match="does not exist"):
        service.ingest(missing, expected_tenant="eng_tenanta00001")

    revision = make_knowledge(
        unit_id="ku_revision0001",
        tenant_scope="eng_tenanta00001",
        supersedes=original.unit_id,
    )
    stored = service.ingest(revision, expected_tenant="eng_tenanta00001")
    assert stored.supersedes == original.unit_id

    cross_tenant = make_knowledge(
        unit_id="ku_revision0002",
        tenant_scope="eng_tenantb00001",
        supersedes=original.unit_id,
    )
    with pytest.raises(KnowledgeConflict, match="same tenant"):
        service.ingest(cross_tenant, expected_tenant="eng_tenantb00001")


def test_freshness_floor_excludes_stale_units(service: KnowledgeService) -> None:
    stale = make_knowledge(
        unit_id="ku_stale000001",
        title="Stale quasar note",
        freshness_at=utc_now() - timedelta(days=500),
    )
    fresh = make_knowledge(unit_id="ku_fresh000001", title="Fresh quasar note")
    service.ingest(stale)
    service.ingest(fresh)

    default = service.retrieve(RetrievalQuery(text="quasar"), tenant_scope="global")
    assert {result.unit.unit_id for result in default} == {fresh.unit_id}
    assert not service.is_fresh(stale)

    all_units = service.retrieve(
        RetrievalQuery(text="quasar"), tenant_scope="global", allow_stale=True
    )
    assert {result.unit.unit_id for result in all_units} == {fresh.unit_id, stale.unit_id}


def test_explicit_freshness_filter_wins(service: KnowledgeService) -> None:
    unit = make_knowledge(unit_id="ku_fresh000001", freshness_at=utc_now() - timedelta(days=10))
    service.ingest(unit)
    results = service.retrieve(
        RetrievalQuery(
            text="",
            require_fresh_after=utc_now() - timedelta(days=30),
        ),
        tenant_scope="global",
    )
    assert [result.unit.unit_id for result in results] == [unit.unit_id]

    excluded = service.retrieve(
        RetrievalQuery(
            text="",
            require_fresh_after=utc_now() - timedelta(days=1),
        ),
        tenant_scope="global",
    )
    assert excluded == ()


def test_empty_tenant_is_rejected(service: KnowledgeService) -> None:
    with pytest.raises(KnowledgeAccessDenied):
        service.retrieve(RetrievalQuery(tenant_scope=""), tenant_scope="global")


def test_seed_tiers_include_verification_guidance(service: KnowledgeService) -> None:
    units = service.install_seeds()
    assert any(unit.tier is KnowledgeTier.VERIFICATION for unit in units)
    assert any("differential" in unit.title.lower() for unit in units)
