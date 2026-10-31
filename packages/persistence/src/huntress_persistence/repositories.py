"""Typed repositories over SQLite.

Every durable record is stored as canonical Pydantic JSON plus a small set of
indexed columns. This keeps the schema migration-friendly while allowing the
queries the controller actually needs.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Callable, Iterable, Sequence
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Generic, TypeVar, cast

from huntress_contracts import (
    ActionLedgerEntry,
    ActionRequest,
    ApprovalRecord,
    ApprovalRequest,
    ApprovalStatus,
    AuditChainVerification,
    AuditEvent,
    BudgetLimits,
    BudgetReservation,
    BudgetReservationStatus,
    BudgetUsage,
    Checkpoint,
    Contract,
    Engagement,
    HostRequestCount,
    HumanReviewRecord,
    InvestigationDecision,
    KnowledgeUnit,
    ModelCallRecord,
    ReasonCode,
    RetrievalQuery,
    RetrievedKnowledge,
    ScopeDocument,
    StateTransition,
    TargetRecord,
    TestAttempt,
    ToolFinding,
    ValidatedFinding,
    ValidationStatus,
    VulnerabilityHypothesis,
    VulnerabilityReport,
    model_self_hash,
    utc_now,
)
from huntress_governance import BudgetExceeded

from .db import Database

T = TypeVar("T", bound=Contract)
Extractor = Callable[[T], object]


def _sql_value(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat()
    if value is None:
        return None
    return value


def _parse_dt(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed.astimezone(UTC)


class JsonRepository(Generic[T]):  # noqa: UP046 - shared TypeVar with Extractor
    """Generic immutable-record repository with indexed columns."""

    def __init__(
        self,
        database: Database,
        *,
        table: str,
        id_column: str,
        model: type[T],
        columns: dict[str, Extractor[T]],
        order_by: str = "rowid",
    ) -> None:
        self.database = database
        self.table = table
        self.id_column = id_column
        self.model = model
        self.columns = columns
        self.order_by = order_by

    def _upsert_sql(self) -> str:
        all_columns = [self.id_column, *self.columns.keys(), "record_json"]
        placeholders = ", ".join("?" for _ in all_columns)
        updates = ", ".join(
            f"{column} = excluded.{column}" for column in [*self.columns.keys(), "record_json"]
        )
        return (
            f"INSERT INTO {self.table} ({', '.join(all_columns)}) VALUES ({placeholders}) "
            f"ON CONFLICT({self.id_column}) DO UPDATE SET {updates}"
        )

    def _values(self, record: T) -> tuple[object, ...]:
        return (
            _sql_value(getattr(record, self.id_column)),
            *(_sql_value(extractor(record)) for extractor in self.columns.values()),
            record.model_dump_json(),
        )

    def save(self, record: T) -> T:
        self.save_many((record,))
        return record

    def save_many(self, records: Iterable[T]) -> int:
        rows = list(records)
        if not rows:
            return 0
        sql = self._upsert_sql()
        with self.database.transaction() as connection:
            for record in rows:
                connection.execute(sql, self._values(record))
        return len(rows)

    def get(self, record_id: str) -> T | None:
        row = self.database.query_one(
            f"SELECT record_json FROM {self.table} WHERE {self.id_column} = ?", (record_id,)
        )
        return self.model.model_validate_json(row["record_json"]) if row else None

    def all(
        self,
        *,
        where: str = "",
        params: Sequence[object] = (),
        order_by: str | None = None,
        limit: int | None = None,
    ) -> list[T]:
        sql = f"SELECT record_json FROM {self.table}"
        if where:
            sql += f" WHERE {where}"
        sql += f" ORDER BY {order_by or self.order_by}"
        if limit is not None:
            sql += f" LIMIT {int(limit)}"
        rows = self.database.query(sql, tuple(params))
        return [self.model.model_validate_json(row["record_json"]) for row in rows]

    def count(self, *, where: str = "", params: Sequence[object] = ()) -> int:
        sql = f"SELECT COUNT(*) FROM {self.table}"
        if where:
            sql += f" WHERE {where}"
        row = self.database.query_one(sql, tuple(params))
        return int(row[0]) if row else 0


class EngagementRepository:
    def __init__(self, database: Database) -> None:
        self._repo = JsonRepository(
            database,
            table="engagements",
            id_column="engagement_id",
            model=Engagement,
            columns={
                "mode": lambda r: r.mode,
                "state": lambda r: r.state,
                "program_id": lambda r: r.program_id,
                "scope_id": lambda r: r.scope_id,
                "scope_version": lambda r: r.scope_version,
                "policy_version": lambda r: r.policy_version,
                "created_at": lambda r: r.created_at,
                "updated_at": lambda r: r.updated_at,
                "created_by": lambda r: r.created_by,
                "budget_limits_json": lambda r: r.budget_limits.model_dump_json(),
            },
            order_by="created_at",
        )
        self.database = database

    def save(self, engagement: Engagement) -> Engagement:
        return self._repo.save(engagement)

    def get(self, engagement_id: str) -> Engagement | None:
        return self._repo.get(engagement_id)

    def list_all(self, limit: int = 100) -> list[Engagement]:
        return self._repo.all(limit=limit)

    def list_by_state(self, state: str, limit: int = 100) -> list[Engagement]:
        return self._repo.all(where="state = ?", params=(state,), limit=limit)


class ScopeRepository:
    def __init__(self, database: Database) -> None:
        self._repo = JsonRepository(
            database,
            table="scopes",
            id_column="scope_id",
            model=ScopeDocument,
            columns={
                "engagement_id": lambda r: r.engagement_id,
                "version": lambda r: r.version,
                "content_hash": lambda r: r.content_hash,
                "signature": lambda r: r.signature,
                "approved_by": lambda r: r.approved_by,
                "approved_at": lambda r: r.approved_at,
            },
            order_by="version DESC",
        )
        self.database = database

    def save(self, scope: ScopeDocument) -> ScopeDocument:
        return self._repo.save(scope)

    def get(self, scope_id: str) -> ScopeDocument | None:
        return self._repo.get(scope_id)

    def latest(self, engagement_id: str) -> ScopeDocument | None:
        rows = self._repo.all(
            where="engagement_id = ?", params=(engagement_id,), order_by="version DESC", limit=1
        )
        return rows[0] if rows else None

    def versions(self, engagement_id: str) -> list[ScopeDocument]:
        return self._repo.all(where="engagement_id = ?", params=(engagement_id,), order_by="version DESC")


class TargetRepository:
    def __init__(self, database: Database) -> None:
        self._repo = JsonRepository(
            database,
            table="targets",
            id_column="target_id",
            model=TargetRecord,
            columns={
                "engagement_id": lambda r: r.engagement_id,
                "asset_id": lambda r: r.asset_id,
                "host": lambda r: r.host,
                "scheme": lambda r: r.scheme,
                "port": lambda r: r.port,
                "base_url": lambda r: r.base_url,
                "in_scope": lambda r: r.in_scope,
                "first_seen": lambda r: r.first_seen,
                "last_seen": lambda r: r.last_seen,
            },
            order_by="host",
        )
        self.database = database

    def save_many(self, targets: Iterable[TargetRecord]) -> int:
        return self._repo.save_many(targets)

    def save(self, target: TargetRecord) -> TargetRecord:
        return self._repo.save(target)

    def get(self, target_id: str) -> TargetRecord | None:
        return self._repo.get(target_id)

    def list_by_engagement(self, engagement_id: str) -> list[TargetRecord]:
        return self._repo.all(where="engagement_id = ?", params=(engagement_id,))

    def find_by_host(self, engagement_id: str, host: str) -> list[TargetRecord]:
        return self._repo.all(where="engagement_id = ? AND host = ?", params=(engagement_id, host))


class FindingRepository:
    def __init__(self, database: Database) -> None:
        self._repo = JsonRepository(
            database,
            table="tool_findings",
            id_column="finding_id",
            model=ToolFinding,
            columns={
                "engagement_id": lambda r: r.engagement_id,
                "target_id": lambda r: r.target_id,
                "profile_id": lambda r: r.tool_profile_id,
                "finding_type": lambda r: r.finding_type,
                "confidence": lambda r: r.confidence,
                "observed_at": lambda r: r.observed_at,
            },
            order_by="observed_at",
        )
        self.database = database

    def save_many(self, findings: Iterable[ToolFinding]) -> int:
        return self._repo.save_many(findings)

    def get(self, finding_id: str) -> ToolFinding | None:
        return self._repo.get(finding_id)

    def list_by_engagement(self, engagement_id: str, limit: int = 5000) -> list[ToolFinding]:
        return self._repo.all(
            where="engagement_id = ?", params=(engagement_id,), order_by="observed_at", limit=limit
        )

    def list_by_target(self, engagement_id: str, target_id: str) -> list[ToolFinding]:
        return self._repo.all(
            where="engagement_id = ? AND target_id = ?",
            params=(engagement_id, target_id),
            order_by="observed_at",
        )


class HypothesisRepository:
    def __init__(self, database: Database) -> None:
        self._repo = JsonRepository(
            database,
            table="hypotheses",
            id_column="hypothesis_id",
            model=VulnerabilityHypothesis,
            columns={
                "engagement_id": lambda r: r.engagement_id,
                "target_id": lambda r: r.target_id,
                "bug_class_id": lambda r: r.bug_class_id,
                "status": lambda r: r.status,
                "created_at": lambda r: r.created_at,
            },
            order_by="created_at",
        )
        self.database = database

    def save(self, hypothesis: VulnerabilityHypothesis) -> VulnerabilityHypothesis:
        return self._repo.save(hypothesis)

    def get(self, hypothesis_id: str) -> VulnerabilityHypothesis | None:
        return self._repo.get(hypothesis_id)

    def list_by_engagement(self, engagement_id: str) -> list[VulnerabilityHypothesis]:
        return self._repo.all(where="engagement_id = ?", params=(engagement_id,))


class DecisionRepository:
    def __init__(self, database: Database) -> None:
        self._repo = JsonRepository(
            database,
            table="decisions",
            id_column="decision_id",
            model=InvestigationDecision,
            columns={
                "engagement_id": lambda r: r.engagement_id,
                "action": lambda r: r.action,
                "created_at": lambda r: r.created_at,
            },
            order_by="created_at",
        )
        self.database = database

    def save(self, decision: InvestigationDecision) -> InvestigationDecision:
        return self._repo.save(decision)

    def get(self, decision_id: str) -> InvestigationDecision | None:
        return self._repo.get(decision_id)

    def list_by_engagement(self, engagement_id: str) -> list[InvestigationDecision]:
        return self._repo.all(where="engagement_id = ?", params=(engagement_id,))


class ActionRequestRepository:
    """Durable pending action requests used to rebuild approvals after restart."""

    def __init__(self, database: Database) -> None:
        self._repo = JsonRepository(
            database,
            table="action_requests",
            id_column="request_id",
            model=ActionRequest,
            columns={
                "engagement_id": lambda r: r.engagement_id,
                "target_id": lambda r: r.target_id,
                "profile_id": lambda r: r.profile_id,
                "requested_at": lambda r: r.requested_at,
            },
            order_by="requested_at",
        )

    def save(self, request: ActionRequest) -> ActionRequest:
        return self._repo.save(request)

    def get(self, request_id: str) -> ActionRequest | None:
        return self._repo.get(request_id)

    def list_by_engagement(self, engagement_id: str) -> list[ActionRequest]:
        return self._repo.all(where="engagement_id = ?", params=(engagement_id,))


class AttemptRepository:
    def __init__(self, database: Database) -> None:
        self._repo = JsonRepository(
            database,
            table="attempts",
            id_column="attempt_id",
            model=TestAttempt,
            columns={
                "engagement_id": lambda r: r.engagement_id,
                "target_id": lambda r: r.target_id,
                "profile_id": lambda r: r.profile_id,
                "status": lambda r: r.status,
                "started_at": lambda r: r.started_at,
            },
            order_by="started_at",
        )
        self.database = database

    def save(self, attempt: TestAttempt) -> TestAttempt:
        return self._repo.save(attempt)

    def get(self, attempt_id: str) -> TestAttempt | None:
        return self._repo.get(attempt_id)

    def list_by_engagement(self, engagement_id: str) -> list[TestAttempt]:
        return self._repo.all(where="engagement_id = ?", params=(engagement_id,))


class ValidationRepository:
    def __init__(self, database: Database) -> None:
        self._repo = JsonRepository(
            database,
            table="validated_findings",
            id_column="finding_id",
            model=ValidatedFinding,
            columns={
                "engagement_id": lambda r: r.engagement_id,
                "target_id": lambda r: r.target_id,
                "bug_class_id": lambda r: r.bug_class_id,
                "status": lambda r: r.status,
                "dedup_fingerprint": lambda r: r.dedup.fingerprint,
                "human_review_status": lambda r: r.human_review_status,
                "validated_at": lambda r: r.validated_at,
            },
            order_by="validated_at",
        )
        self.database = database

    def save(self, finding: ValidatedFinding) -> ValidatedFinding:
        return self._repo.save(finding)

    def get(self, finding_id: str) -> ValidatedFinding | None:
        return self._repo.get(finding_id)

    def list_by_engagement(self, engagement_id: str) -> list[ValidatedFinding]:
        return self._repo.all(where="engagement_id = ?", params=(engagement_id,))

    def list_passed(self, engagement_id: str) -> list[ValidatedFinding]:
        return self._repo.all(
            where="engagement_id = ? AND status = ?",
            params=(engagement_id, ValidationStatus.PASSED.value),
        )

    def find_by_fingerprint(self, engagement_id: str, fingerprint: str) -> list[ValidatedFinding]:
        return self._repo.all(
            where="engagement_id = ? AND dedup_fingerprint = ?",
            params=(engagement_id, fingerprint),
        )


class ReviewRepository:
    def __init__(self, database: Database) -> None:
        self._repo = JsonRepository(
            database,
            table="reviews",
            id_column="review_id",
            model=HumanReviewRecord,
            columns={
                "engagement_id": lambda r: r.engagement_id,
                "finding_id": lambda r: r.finding_id,
                "decision": lambda r: r.decision,
                "reviewed_at": lambda r: r.reviewed_at,
            },
            order_by="reviewed_at",
        )
        self.database = database

    def save(self, review: HumanReviewRecord) -> HumanReviewRecord:
        return self._repo.save(review)

    def list_for_finding(self, finding_id: str) -> list[HumanReviewRecord]:
        return self._repo.all(where="finding_id = ?", params=(finding_id,))


class ReportRepository:
    def __init__(self, database: Database) -> None:
        self._repo = JsonRepository(
            database,
            table="reports",
            id_column="report_id",
            model=VulnerabilityReport,
            columns={
                "engagement_id": lambda r: r.engagement_id,
                "status": lambda r: r.status,
                "content_hash": lambda r: r.content_hash,
                "generated_at": lambda r: r.generated_at,
            },
            order_by="generated_at",
        )
        self.database = database

    def save(self, report: VulnerabilityReport) -> VulnerabilityReport:
        return self._repo.save(report)

    def get(self, report_id: str) -> VulnerabilityReport | None:
        return self._repo.get(report_id)

    def list_by_engagement(self, engagement_id: str) -> list[VulnerabilityReport]:
        return self._repo.all(where="engagement_id = ?", params=(engagement_id,))


class ApprovalRepository:
    def __init__(self, database: Database) -> None:
        self.database = database
        self._requests = JsonRepository(
            database,
            table="approval_requests",
            id_column="approval_id",
            model=ApprovalRequest,
            columns={
                "engagement_id": lambda r: r.engagement_id,
                "request_id": lambda r: r.request_id,
                "action_fingerprint": lambda r: r.action_fingerprint,
                "scope_hash": lambda r: r.scope_hash,
                "status": lambda r: r.status,
                "requested_at": lambda r: r.requested_at,
                "expires_at": lambda r: r.expires_at,
            },
            order_by="requested_at",
        )
        self._records = JsonRepository(
            database,
            table="approvals",
            id_column="approval_id",
            model=ApprovalRecord,
            columns={
                "engagement_id": lambda r: r.engagement_id,
                "request_id": lambda r: r.request_id,
                "action_fingerprint": lambda r: r.action_fingerprint,
                "scope_hash": lambda r: r.scope_hash,
                "status": lambda r: r.status,
                "approved_by": lambda r: r.approved_by,
                "approved_at": lambda r: r.approved_at,
                "expires_at": lambda r: r.expires_at,
            },
            order_by="approved_at",
        )

    def save_request(self, request: ApprovalRequest) -> ApprovalRequest:
        return self._requests.save(request)

    def get_request(self, approval_id: str) -> ApprovalRequest | None:
        return self._requests.get(approval_id)

    def list_pending(self, engagement_id: str) -> list[ApprovalRequest]:
        return self._requests.all(
            where="engagement_id = ? AND status = ?",
            params=(engagement_id, ApprovalStatus.PENDING.value),
        )

    def save_record(self, record: ApprovalRecord) -> ApprovalRecord:
        return self._records.save(record)

    def get_approval(self, approval_id: str) -> ApprovalRecord | None:
        return self._records.get(approval_id)

    def list_records(self, engagement_id: str) -> list[ApprovalRecord]:
        return self._records.all(where="engagement_id = ?", params=(engagement_id,))


class LedgerRepository:
    """SQLite-backed idempotency ledger."""

    def __init__(self, database: Database) -> None:
        self.database = database
        self._repo = JsonRepository(
            database,
            table="action_ledger",
            id_column="idempotency_key",
            model=ActionLedgerEntry,
            columns={
                "request_id": lambda r: r.request_id,
                "engagement_id": lambda r: r.engagement_id,
                "action_fingerprint": lambda r: r.action_fingerprint,
                "status": lambda r: r.status,
                "reserved_at": lambda r: r.reserved_at,
                "updated_at": lambda r: r.updated_at,
                "result_ref": lambda r: r.result_ref,
                "error_code": lambda r: r.error_code,
            },
            order_by="updated_at",
        )

    def get(self, idempotency_key: str) -> ActionLedgerEntry | None:
        return self._repo.get(idempotency_key)

    def reserve(self, entry: ActionLedgerEntry) -> bool:
        """Insert only if absent. Returns False when the key already exists."""

        sql = (
            "INSERT OR IGNORE INTO action_ledger "
            "(idempotency_key, request_id, engagement_id, action_fingerprint, status, "
            "reserved_at, updated_at, result_ref, error_code, record_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        values = (
            entry.idempotency_key,
            entry.request_id,
            entry.engagement_id,
            entry.action_fingerprint,
            entry.status.value,
            entry.reserved_at.isoformat(),
            entry.updated_at.isoformat(),
            entry.result_ref,
            entry.error_code,
            entry.model_dump_json(),
        )
        with self.database.transaction() as connection:
            cursor = connection.execute(sql, values)
            return cursor.rowcount == 1

    def update(self, entry: ActionLedgerEntry) -> None:
        self._repo.save(entry)

    def list_by_engagement(self, engagement_id: str) -> list[ActionLedgerEntry]:
        return self._repo.all(where="engagement_id = ?", params=(engagement_id,))


class BudgetRepository:
    """Transactional budget and per-host rate accounting."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def _ensure_usage(
        self, connection: sqlite3.Connection, engagement_id: str, now: datetime
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM budget_usage WHERE engagement_id = ?", (engagement_id,)
        ).fetchone()
        if row is None:
            connection.execute(
                "INSERT INTO budget_usage (engagement_id, window_started_at, started_at) VALUES (?, ?, ?)",
                (engagement_id, now.isoformat(), now.isoformat()),
            )
            row = connection.execute(
                "SELECT * FROM budget_usage WHERE engagement_id = ?", (engagement_id,)
            ).fetchone()
        assert row is not None
        window_started = _parse_dt(row["window_started_at"])
        if now - window_started >= timedelta(minutes=1):
            connection.execute(
                "UPDATE budget_usage SET requests_total = 0, window_started_at = ? "
                "WHERE engagement_id = ?",
                (now.isoformat(), engagement_id),
            )
            connection.execute(
                "DELETE FROM host_rate_windows WHERE engagement_id = ?", (engagement_id,)
            )
            row = connection.execute(
                "SELECT * FROM budget_usage WHERE engagement_id = ?", (engagement_id,)
            ).fetchone()
            assert row is not None
        started = _parse_dt(row["started_at"])
        wall_clock = max(0, int((now - started).total_seconds()))
        connection.execute(
            "UPDATE budget_usage SET wall_clock_seconds_used = ? WHERE engagement_id = ?",
            (wall_clock, engagement_id),
        )
        row = connection.execute(
            "SELECT * FROM budget_usage WHERE engagement_id = ?", (engagement_id,)
        ).fetchone()
        assert row is not None
        return cast(sqlite3.Row, row)

    def get_usage(self, engagement_id: str) -> BudgetUsage:
        now = utc_now()
        with self.database.transaction() as connection:
            row = self._ensure_usage(connection, engagement_id, now)
            host_rows = connection.execute(
                "SELECT host, count FROM host_rate_windows WHERE engagement_id = ? ORDER BY host",
                (engagement_id,),
            ).fetchall()
        return BudgetUsage(
            actions_used=int(row["actions_used"]),
            model_calls_used=int(row["model_calls_used"]),
            tokens_used=int(row["tokens_used"]),
            cost_usd_used=float(row["cost_usd_used"]),
            wall_clock_seconds_used=int(row["wall_clock_seconds_used"]),
            requests_total=int(row["requests_total"]),
            host_request_counts=tuple(
                HostRequestCount(host=str(h["host"]), requests=int(h["count"])) for h in host_rows
            ),
        )

    def reserve(
        self,
        engagement_id: str,
        limits: BudgetLimits,
        reservation: BudgetReservation,
    ) -> BudgetReservation:
        now = utc_now()
        with self.database.transaction() as connection:
            row = self._ensure_usage(connection, engagement_id, now)
            if int(row["actions_used"]) + reservation.actions > limits.max_actions:
                raise BudgetExceeded("action budget exhausted")
            if int(row["model_calls_used"]) + reservation.model_calls > limits.max_model_calls:
                raise BudgetExceeded("model-call budget exhausted")
            if int(row["tokens_used"]) + reservation.tokens > limits.max_tokens:
                raise BudgetExceeded("token budget exhausted")
            if float(row["cost_usd_used"]) + reservation.cost_usd > limits.max_cost_usd + 1e-9:
                raise BudgetExceeded("cost budget exhausted")
            if (
                int(row["requests_total"]) + reservation.requests
                > limits.max_requests_per_engagement_per_minute
            ):
                raise BudgetExceeded(
                    "engagement rate limit exceeded", reason_code=ReasonCode.DENIED_RATE_LIMITED
                )
            if reservation.host and reservation.requests:
                host_row = connection.execute(
                    "SELECT count FROM host_rate_windows WHERE engagement_id = ? AND host = ?",
                    (engagement_id, reservation.host),
                ).fetchone()
                current = int(host_row["count"]) if host_row else 0
                if current + reservation.requests > limits.max_requests_per_host_per_minute:
                    raise BudgetExceeded(
                        "host rate limit exceeded", reason_code=ReasonCode.DENIED_RATE_LIMITED
                    )
                connection.execute(
                    "INSERT INTO host_rate_windows (engagement_id, host, window_started_at, count) "
                    "VALUES (?, ?, ?, ?) ON CONFLICT(engagement_id, host) DO UPDATE SET "
                    "count = count + excluded.count, window_started_at = excluded.window_started_at",
                    (engagement_id, reservation.host, now.isoformat(), reservation.requests),
                )
            connection.execute(
                "UPDATE budget_usage SET actions_used = actions_used + ?, "
                "model_calls_used = model_calls_used + ?, tokens_used = tokens_used + ?, "
                "cost_usd_used = cost_usd_used + ?, requests_total = requests_total + ? "
                "WHERE engagement_id = ?",
                (
                    reservation.actions,
                    reservation.model_calls,
                    reservation.tokens,
                    reservation.cost_usd,
                    reservation.requests,
                    engagement_id,
                ),
            )
            connection.execute(
                "INSERT INTO budget_reservations "
                "(reservation_id, engagement_id, request_id, idempotency_key, host, requests, "
                "actions, model_calls, tokens, cost_usd, status, created_at, settled_at, record_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    reservation.reservation_id,
                    engagement_id,
                    reservation.request_id,
                    reservation.idempotency_key,
                    reservation.host,
                    reservation.requests,
                    reservation.actions,
                    reservation.model_calls,
                    reservation.tokens,
                    reservation.cost_usd,
                    reservation.status.value,
                    reservation.created_at.isoformat(),
                    reservation.settled_at.isoformat() if reservation.settled_at else None,
                    reservation.model_dump_json(),
                ),
            )
        return reservation

    def _load_reservation(
        self, connection: sqlite3.Connection, reservation_id: str
    ) -> tuple[sqlite3.Row, BudgetReservation]:
        row = connection.execute(
            "SELECT * FROM budget_reservations WHERE reservation_id = ?", (reservation_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"unknown reservation: {reservation_id}")
        return row, BudgetReservation.model_validate_json(row["record_json"])

    def commit(
        self,
        reservation_id: str,
        *,
        actions: int | None = None,
        tokens: int | None = None,
        cost_usd: float | None = None,
    ) -> None:
        now = utc_now()
        with self.database.transaction() as connection:
            _row, reservation = self._load_reservation(connection, reservation_id)
            if reservation.status is not BudgetReservationStatus.RESERVED:
                return
            actual_actions = reservation.actions if actions is None else max(0, actions)
            actual_tokens = reservation.tokens if tokens is None else max(0, tokens)
            actual_cost = reservation.cost_usd if cost_usd is None else max(0.0, cost_usd)
            connection.execute(
                "UPDATE budget_usage SET actions_used = MAX(0, actions_used + ?), "
                "tokens_used = MAX(0, tokens_used + ?), cost_usd_used = MAX(0, cost_usd_used + ?) "
                "WHERE engagement_id = ?",
                (
                    actual_actions - reservation.actions,
                    actual_tokens - reservation.tokens,
                    actual_cost - reservation.cost_usd,
                    reservation.engagement_id,
                ),
            )
            settled = reservation.model_copy(
                update={
                    "status": BudgetReservationStatus.COMMITTED,
                    "settled_at": now,
                }
            )
            connection.execute(
                "UPDATE budget_reservations SET status = ?, settled_at = ?, record_json = ? "
                "WHERE reservation_id = ?",
                (settled.status.value, now.isoformat(), settled.model_dump_json(), reservation_id),
            )

    def release(self, reservation_id: str) -> None:
        now = utc_now()
        with self.database.transaction() as connection:
            _row, reservation = self._load_reservation(connection, reservation_id)
            if reservation.status is not BudgetReservationStatus.RESERVED:
                return
            connection.execute(
                "UPDATE budget_usage SET actions_used = MAX(0, actions_used - ?), "
                "model_calls_used = MAX(0, model_calls_used - ?), "
                "tokens_used = MAX(0, tokens_used - ?), "
                "cost_usd_used = MAX(0, cost_usd_used - ?), "
                "requests_total = MAX(0, requests_total - ?) WHERE engagement_id = ?",
                (
                    reservation.actions,
                    reservation.model_calls,
                    reservation.tokens,
                    reservation.cost_usd,
                    reservation.requests,
                    reservation.engagement_id,
                ),
            )
            if reservation.host and reservation.requests:
                connection.execute(
                    "UPDATE host_rate_windows SET count = MAX(0, count - ?) "
                    "WHERE engagement_id = ? AND host = ?",
                    (reservation.requests, reservation.engagement_id, reservation.host),
                )
            released = reservation.model_copy(
                update={"status": BudgetReservationStatus.RELEASED, "settled_at": now}
            )
            connection.execute(
                "UPDATE budget_reservations SET status = ?, settled_at = ?, record_json = ? "
                "WHERE reservation_id = ?",
                (released.status.value, now.isoformat(), released.model_dump_json(), reservation_id),
            )

    def get_reservation(self, reservation_id: str) -> BudgetReservation | None:
        row = self.database.query_one(
            "SELECT record_json FROM budget_reservations WHERE reservation_id = ?",
            (reservation_id,),
        )
        return BudgetReservation.model_validate_json(row["record_json"]) if row else None


class AuditRepository:
    """Append-only hash-chained audit log."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def append(self, event: AuditEvent) -> AuditEvent:
        chain_key = event.engagement_id or "__global__"
        with self.database.transaction() as connection:
            last = connection.execute(
                "SELECT event_hash FROM audit_events WHERE chain_key = ? "
                "ORDER BY rowid DESC LIMIT 1",
                (chain_key,),
            ).fetchone()
            prev_hash = str(last["event_hash"]) if last else ""
            pending = event.model_copy(update={"prev_hash": prev_hash, "event_hash": ""})
            digest = model_self_hash(pending, exclude=frozenset({"event_hash"}))
            final = pending.model_copy(update={"event_hash": digest})
            connection.execute(
                "INSERT INTO audit_events "
                "(event_id, chain_key, engagement_id, occurred_at, prev_hash, event_hash, record_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    final.event_id,
                    chain_key,
                    final.engagement_id,
                    final.occurred_at.isoformat(),
                    final.prev_hash,
                    final.event_hash,
                    final.model_dump_json(),
                ),
            )
            return final

    def list_events(self, engagement_id: str | None = None, limit: int = 1000) -> list[AuditEvent]:
        if engagement_id is None:
            rows = self.database.query(
                "SELECT record_json FROM audit_events ORDER BY rowid DESC LIMIT ?", (limit,)
            )
        else:
            rows = self.database.query(
                "SELECT record_json FROM audit_events WHERE engagement_id = ? "
                "ORDER BY rowid ASC LIMIT ?",
                (engagement_id, limit),
            )
        return [AuditEvent.model_validate_json(row["record_json"]) for row in rows]

    def verify_chain(self, engagement_id: str | None = None) -> AuditChainVerification:
        chain_key = engagement_id or "__global__"
        rows = self.database.query(
            "SELECT event_id, chain_key, engagement_id, prev_hash, event_hash, record_json "
            "FROM audit_events WHERE chain_key = ? ORDER BY rowid ASC",
            (chain_key,),
        )
        previous = ""

        def invalid(event_id: str, reason: str) -> AuditChainVerification:
            return AuditChainVerification(
                engagement_id=engagement_id,
                events_checked=len(rows),
                valid=False,
                first_invalid_event_id=event_id,
                reason=reason,
                checked_at=utc_now(),
            )

        for row in rows:
            event = AuditEvent.model_validate_json(row["record_json"])
            # The record is the authoritative event. Cross-check the indexed
            # columns so tampering with only a hash column is detected too.
            if row["event_id"] != event.event_id:
                return invalid(event.event_id, "stored event id does not match record")
            if row["chain_key"] != chain_key:
                return invalid(event.event_id, "stored chain key does not match record")
            if row["engagement_id"] != event.engagement_id:
                return invalid(event.event_id, "stored engagement id does not match record")
            if row["prev_hash"] != event.prev_hash:
                return invalid(event.event_id, "stored previous hash does not match record")
            if row["event_hash"] != event.event_hash:
                return invalid(event.event_id, "stored event hash does not match record")
            if event.prev_hash != previous:
                return invalid(event.event_id, "previous hash does not match")
            recomputed = model_self_hash(
                event.model_copy(update={"event_hash": ""}), exclude=frozenset({"event_hash"})
            )
            if recomputed != event.event_hash:
                return invalid(event.event_id, "event hash mismatch")
            previous = event.event_hash
        return AuditChainVerification(
            engagement_id=engagement_id,
            events_checked=len(rows),
            valid=True,
            checked_at=utc_now(),
        )


class TransitionRepository:
    def __init__(self, database: Database) -> None:
        self._repo = JsonRepository(
            database,
            table="state_transitions",
            id_column="transition_id",
            model=StateTransition,
            columns={
                "engagement_id": lambda r: r.engagement_id,
                "from_state": lambda r: r.from_state,
                "to_state": lambda r: r.to_state,
                "occurred_at": lambda r: r.occurred_at,
            },
            order_by="occurred_at",
        )

    def save(self, transition: StateTransition) -> StateTransition:
        return self._repo.save(transition)

    def list_for(self, engagement_id: str) -> list[StateTransition]:
        return self._repo.all(where="engagement_id = ?", params=(engagement_id,))


class CheckpointRepository:
    def __init__(self, database: Database) -> None:
        self._repo = JsonRepository(
            database,
            table="checkpoints",
            id_column="checkpoint_id",
            model=Checkpoint,
            columns={
                "engagement_id": lambda r: r.engagement_id,
                "state": lambda r: r.state,
                "created_at": lambda r: r.created_at,
            },
            order_by="created_at",
        )

    def save(self, checkpoint: Checkpoint) -> Checkpoint:
        return self._repo.save(checkpoint)

    def latest(self, engagement_id: str) -> Checkpoint | None:
        rows = self._repo.all(
            where="engagement_id = ?", params=(engagement_id,), order_by="created_at DESC", limit=1
        )
        return rows[0] if rows else None


class ModelCallRepository:
    def __init__(self, database: Database) -> None:
        self._repo = JsonRepository(
            database,
            table="model_calls",
            id_column="call_id",
            model=ModelCallRecord,
            columns={
                "engagement_id": lambda r: r.engagement_id,
                "checkpoint": lambda r: r.checkpoint,
                "started_at": lambda r: r.started_at,
            },
            order_by="started_at",
        )

    def save(self, record: ModelCallRecord) -> ModelCallRecord:
        return self._repo.save(record)

    def list_by_engagement(self, engagement_id: str) -> list[ModelCallRecord]:
        return self._repo.all(where="engagement_id = ?", params=(engagement_id,))


class KnowledgeRepository:
    """Metadata-filtered, FTS5-ranked knowledge retrieval."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def upsert(self, unit: KnowledgeUnit) -> KnowledgeUnit:
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT INTO knowledge_units "
                "(unit_id, tenant_scope, tier, domain, component, cwe_csv, oracle_csv, "
                "freshness_at, content_hash, record_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(unit_id) DO UPDATE SET tenant_scope = excluded.tenant_scope, "
                "tier = excluded.tier, domain = excluded.domain, component = excluded.component, "
                "cwe_csv = excluded.cwe_csv, oracle_csv = excluded.oracle_csv, "
                "freshness_at = excluded.freshness_at, content_hash = excluded.content_hash, "
                "record_json = excluded.record_json",
                (
                    unit.unit_id,
                    unit.tenant_scope,
                    unit.tier.value,
                    unit.domain.value if unit.domain else None,
                    unit.component,
                    "," + ",".join(str(c) for c in unit.cwe_ids) + ",",
                    "," + ",".join(o.value for o in unit.oracle_archetypes) + ",",
                    unit.freshness_at.isoformat(),
                    unit.content_hash,
                    unit.model_dump_json(),
                ),
            )
            connection.execute("DELETE FROM knowledge_fts WHERE unit_id = ?", (unit.unit_id,))
            connection.execute(
                "INSERT INTO knowledge_fts (unit_id, title, summary, tags) VALUES (?, ?, ?, ?)",
                (unit.unit_id, unit.title, unit.summary, " ".join(unit.tags)),
            )
        return unit

    def get(self, unit_id: str) -> KnowledgeUnit | None:
        row = self.database.query_one(
            "SELECT record_json FROM knowledge_units WHERE unit_id = ?", (unit_id,)
        )
        return KnowledgeUnit.model_validate_json(row["record_json"]) if row else None

    def search(self, query: RetrievalQuery) -> list[RetrievedKnowledge]:
        filters = ["k.tenant_scope IN ('global', ?)"]
        params: list[object] = [query.tenant_scope]
        if query.tiers:
            placeholders = ", ".join("?" for _ in query.tiers)
            filters.append(f"k.tier IN ({placeholders})")
            params.extend(tier.value for tier in query.tiers)
        if query.domain is not None:
            filters.append("k.domain = ?")
            params.append(query.domain.value)
        if query.component:
            filters.append("k.component LIKE ?")
            params.append(f"%{query.component}%")
        if query.cwe_ids:
            cwe_clauses = []
            for cwe in query.cwe_ids:
                cwe_clauses.append("k.cwe_csv LIKE ?")
                params.append(f"%,{cwe},%")
            filters.append("(" + " OR ".join(cwe_clauses) + ")")
        if query.oracle_archetypes:
            oracle_clauses = []
            for oracle in query.oracle_archetypes:
                oracle_clauses.append("k.oracle_csv LIKE ?")
                params.append(f"%,{oracle.value},%")
            filters.append("(" + " OR ".join(oracle_clauses) + ")")
        if query.require_fresh_after is not None:
            filters.append("k.freshness_at >= ?")
            params.append(query.require_fresh_after.isoformat())

        terms = re.findall(r"[A-Za-z0-9_.:-]{2,}", query.text)
        where_sql = " AND ".join(filters)
        if terms:
            match = " OR ".join(f'"{term}"' for term in terms[:12])
            sql = (
                "SELECT k.record_json, bm25(knowledge_fts) AS rank FROM knowledge_fts "
                "JOIN knowledge_units k ON k.unit_id = knowledge_fts.unit_id "
                f"WHERE knowledge_fts MATCH ? AND {where_sql} ORDER BY rank LIMIT ?"
            )
            rows = self.database.query(sql, (match, *params, query.limit))
            return [
                RetrievedKnowledge(
                    unit=KnowledgeUnit.model_validate_json(row["record_json"]),
                    score=1.0 / (1.0 + abs(float(row["rank"]))),
                    reason="metadata+lexical",
                )
                for row in rows
            ]
        sql = (
            f"SELECT k.record_json FROM knowledge_units k WHERE {where_sql} "
            "ORDER BY k.freshness_at DESC LIMIT ?"
        )
        rows = self.database.query(sql, (*params, query.limit))
        return [
            RetrievedKnowledge(
                unit=KnowledgeUnit.model_validate_json(row["record_json"]),
                score=1.0,
                reason="metadata",
            )
            for row in rows
        ]

    def count(self) -> int:
        row = self.database.query_one("SELECT COUNT(*) FROM knowledge_units")
        return int(row[0]) if row else 0


class RepositoryBundle:
    """Convenience aggregate wired once by the application container."""

    def __init__(self, database: Database) -> None:
        self.database = database
        self.engagements = EngagementRepository(database)
        self.scopes = ScopeRepository(database)
        self.targets = TargetRepository(database)
        self.findings = FindingRepository(database)
        self.hypotheses = HypothesisRepository(database)
        self.decisions = DecisionRepository(database)
        self.action_requests = ActionRequestRepository(database)
        self.attempts = AttemptRepository(database)
        self.validations = ValidationRepository(database)
        self.reviews = ReviewRepository(database)
        self.reports = ReportRepository(database)
        self.approvals = ApprovalRepository(database)
        self.ledger = LedgerRepository(database)
        self.budget = BudgetRepository(database)
        self.audit = AuditRepository(database)
        self.transitions = TransitionRepository(database)
        self.checkpoints = CheckpointRepository(database)
        self.model_calls = ModelCallRepository(database)
        self.knowledge = KnowledgeRepository(database)
