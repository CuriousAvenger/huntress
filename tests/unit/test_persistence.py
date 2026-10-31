"""SQLite persistence, budget transactions, audit chain, and FTS retrieval."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from huntress_contracts import (
    ActionKind,
    ActionLedgerEntry,
    Actor,
    ActorType,
    AuditEvent,
    BudgetLimits,
    BudgetReservation,
    LedgerStatus,
    RetrievalQuery,
    utc_now,
)
from huntress_governance import BudgetExceeded
from huntress_persistence import SCHEMA_VERSION, Database, RepositoryBundle
from tests.helpers import make_engagement, make_knowledge


@pytest.fixture
def database(tmp_path: Path) -> Database:
    db = Database(tmp_path / "huntress.db")
    db.migrate()
    return db


@pytest.fixture
def repos(database: Database) -> RepositoryBundle:
    return RepositoryBundle(database)


def _audit_event(engagement_id: str, action: str = "pytest_event") -> AuditEvent:
    return AuditEvent(
        event_id="aud_" + action.replace("_", "")[:12].ljust(12, "0"),
        occurred_at=utc_now(),
        engagement_id=engagement_id,
        actor=Actor(type=ActorType.SYSTEM, id="pytest"),
        action=action,
        outcome="ok",
        correlation_id="corr-pytest",
    )


def _ledger_entry(engagement_id: str, key: str = "act:pytest-0001") -> ActionLedgerEntry:
    now = utc_now()
    return ActionLedgerEntry(
        idempotency_key=key,
        request_id="req_pytest000001",
        engagement_id=engagement_id,
        action_fingerprint="a" * 64,
        status=LedgerStatus.RESERVED,
        reserved_at=now,
        updated_at=now,
    )


def _reservation(
    engagement_id: str,
    *,
    reservation_id: str = "br_pytest000001",
    actions: int = 1,
    requests: int = 1,
    host: str = "127.0.0.1",
    tokens: int = 0,
    model_calls: int = 0,
) -> BudgetReservation:
    return BudgetReservation(
        reservation_id=reservation_id,
        engagement_id=engagement_id,
        request_id="req_pytest000001",
        idempotency_key=f"act:{reservation_id}",
        host=host,
        requests=requests,
        actions=actions,
        tokens=tokens,
        model_calls=model_calls,
        created_at=utc_now(),
    )


def test_migrations_are_idempotent_and_healthy(database: Database) -> None:
    assert database.migrate() == SCHEMA_VERSION
    health = database.health()
    assert health["schema_version"] == 2
    assert health["integrity"] == "ok"
    assert health["journal_mode"].lower() == "wal"


def test_engagement_roundtrip_and_listing(repos: RepositoryBundle) -> None:
    engagement = make_engagement()
    repos.engagements.save(engagement)
    assert repos.engagements.get(engagement.engagement_id) == engagement
    assert [item.engagement_id for item in repos.engagements.list_by_state("READY")] == [
        engagement.engagement_id
    ]
    assert len(repos.engagements.list_all()) == 1


def test_action_requests_survive_restart(repos: RepositoryBundle) -> None:
    from huntress_contracts import ActionRequest

    engagement = make_engagement()
    request = ActionRequest(
        request_id="req_pytest000001",
        engagement_id=engagement.engagement_id,
        action=ActionKind.RUN_APPROVED_PROFILE,
        target_id="tgt_pytest000001",
        profile_id="http.open_redirect",
        idempotency_key="act:req_pytest000001",
        requested_by="pytest",
        requested_at=utc_now(),
    )
    repos.action_requests.save(request)
    assert repos.action_requests.get(request.request_id) == request
    stored_requests = repos.action_requests.list_by_engagement(engagement.engagement_id)
    assert [item.request_id for item in stored_requests] == [request.request_id]


def test_ledger_reservation_is_atomic(repos: RepositoryBundle) -> None:
    engagement = make_engagement()
    entry = _ledger_entry(engagement.engagement_id)
    assert repos.ledger.reserve(entry)
    assert not repos.ledger.reserve(entry)
    assert repos.ledger.get(entry.idempotency_key) == entry

    executing = entry.model_copy(update={"status": LedgerStatus.EXECUTING, "updated_at": utc_now()})
    repos.ledger.update(executing)
    assert repos.ledger.get(entry.idempotency_key).status is LedgerStatus.EXECUTING  # type: ignore[union-attr]


def test_budget_reserve_commit_and_release(repos: RepositoryBundle) -> None:
    engagement = make_engagement()
    limits = BudgetLimits(max_actions=5, max_requests_per_host_per_minute=5)
    first = _reservation(engagement.engagement_id, reservation_id="br_pytest000001", actions=2)
    repos.budget.reserve(engagement.engagement_id, limits, first)
    assert repos.budget.get_usage(engagement.engagement_id).actions_used == 2

    repos.budget.commit(first.reservation_id, actions=1)
    usage = repos.budget.get_usage(engagement.engagement_id)
    assert usage.actions_used == 1
    assert repos.budget.get_reservation(first.reservation_id).status.value == "committed"  # type: ignore[union-attr]

    second = _reservation(engagement.engagement_id, reservation_id="br_pytest000002", actions=2)
    repos.budget.reserve(engagement.engagement_id, limits, second)
    assert repos.budget.get_usage(engagement.engagement_id).actions_used == 3
    repos.budget.release(second.reservation_id)
    assert repos.budget.get_usage(engagement.engagement_id).actions_used == 1
    assert repos.budget.get_reservation(second.reservation_id).status.value == "released"  # type: ignore[union-attr]


def test_budget_rejects_over_limit_and_host_rate(repos: RepositoryBundle) -> None:
    engagement = make_engagement()
    limits = BudgetLimits(
        max_actions=2,
        max_requests_per_host_per_minute=2,
        max_requests_per_engagement_per_minute=10,
    )
    with pytest.raises(BudgetExceeded, match="action budget"):
        repos.budget.reserve(
            engagement.engagement_id,
            limits,
            _reservation(engagement.engagement_id, actions=3),
        )

    repos.budget.reserve(
        engagement.engagement_id,
        limits,
        _reservation(engagement.engagement_id, requests=2),
    )
    with pytest.raises(BudgetExceeded, match="host rate limit"):
        repos.budget.reserve(
            engagement.engagement_id,
            limits,
            _reservation(engagement.engagement_id, reservation_id="br_pytest000002"),
        )


def test_budget_commit_is_idempotent(repos: RepositoryBundle) -> None:
    engagement = make_engagement()
    limits = BudgetLimits(max_actions=5)
    reservation = _reservation(engagement.engagement_id, actions=2)
    repos.budget.reserve(engagement.engagement_id, limits, reservation)
    repos.budget.commit(reservation.reservation_id, actions=1)
    repos.budget.commit(reservation.reservation_id, actions=5)
    assert repos.budget.get_usage(engagement.engagement_id).actions_used == 1


def test_audit_chain_appends_and_detects_tampering(database: Database, repos: RepositoryBundle) -> None:
    engagement = make_engagement()
    first = repos.audit.append(_audit_event(engagement.engagement_id, "first_event"))
    second = repos.audit.append(_audit_event(engagement.engagement_id, "second_event"))
    assert first.prev_hash == ""
    assert second.prev_hash == first.event_hash

    verification = repos.audit.verify_chain(engagement.engagement_id)
    assert verification.valid
    assert verification.events_checked == 2

    row = database.query_one(
        "SELECT record_json FROM audit_events WHERE event_id = ?", (first.event_id,)
    )
    assert row is not None
    tampered = json.loads(row["record_json"])
    tampered["action"] = "tampered_action"
    database.execute(
        "UPDATE audit_events SET record_json = ? WHERE event_id = ?",
        (json.dumps(tampered), first.event_id),
    )
    broken = repos.audit.verify_chain(engagement.engagement_id)
    assert not broken.valid
    assert broken.first_invalid_event_id == first.event_id


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("event_hash", "0" * 64),
        ("prev_hash", "0" * 64),
        ("event_id", "aud_tampered0001"),
        ("engagement_id", "eng_tampered0001"),
    ],
)
def test_audit_chain_detects_indexed_column_tampering(
    database: Database, repos: RepositoryBundle, column: str, value: str
) -> None:
    engagement = make_engagement()
    first = repos.audit.append(_audit_event(engagement.engagement_id, "first_event"))
    repos.audit.append(_audit_event(engagement.engagement_id, "second_event"))

    database.execute(
        f"UPDATE audit_events SET {column} = ? WHERE event_id = ?",
        (value, first.event_id),
    )
    broken = repos.audit.verify_chain(engagement.engagement_id)
    assert not broken.valid
    assert broken.first_invalid_event_id == first.event_id
    assert "does not match record" in broken.reason


def test_knowledge_fts_and_tenant_isolation(repos: RepositoryBundle) -> None:
    engagement_a = make_engagement()
    engagement_b = make_engagement()
    global_unit = make_knowledge(unit_id="ku_global000001", title="Quasar technique")
    tenant_a_unit = make_knowledge(
        unit_id="ku_tenanta00001",
        tenant_scope=engagement_a.engagement_id,
        title="Quasar engagement note",
    )
    tenant_b_unit = make_knowledge(
        unit_id="ku_tenantb00001",
        tenant_scope=engagement_b.engagement_id,
        title="Nebula engagement note",
    )
    for unit in (global_unit, tenant_a_unit, tenant_b_unit):
        repos.knowledge.upsert(unit)

    results = repos.knowledge.search(
        RetrievalQuery(tenant_scope=engagement_a.engagement_id, text="Quasar")
    )
    ids = {result.unit.unit_id for result in results}
    assert global_unit.unit_id in ids
    assert tenant_a_unit.unit_id in ids
    assert tenant_b_unit.unit_id not in ids

    filtered = repos.knowledge.search(
        RetrievalQuery(
            tenant_scope=engagement_a.engagement_id,
            cwe_ids=(89,),
            limit=10,
        )
    )
    assert filtered
    assert all(89 in result.unit.cwe_ids for result in filtered)
    assert repos.knowledge.count() == 3


def test_scope_versions_are_ordered(repos: RepositoryBundle) -> None:
    from huntress_execution import ALL_PROFILES
    from huntress_governance import ScopeCompiler
    from tests.conftest import make_scope_draft

    engagement = make_engagement(state="SCOPE_PENDING")  # type: ignore[arg-type]
    draft = make_scope_draft(engagement_id=engagement.engagement_id, url="http://127.0.0.1:8080")
    compiler = ScopeCompiler(b"k" * 32)
    first = compiler.compile(
        draft, profiles=ALL_PROFILES, approved_by="pytest", scope_id="scope_pytest000001", version=1
    )
    second = compiler.compile(
        draft, profiles=ALL_PROFILES, approved_by="pytest", scope_id="scope_pytest000002", version=2
    )
    repos.scopes.save(first)
    repos.scopes.save(second)
    assert repos.scopes.latest(engagement.engagement_id).version == 2  # type: ignore[union-attr]
    assert [scope.version for scope in repos.scopes.versions(engagement.engagement_id)] == [2, 1]
