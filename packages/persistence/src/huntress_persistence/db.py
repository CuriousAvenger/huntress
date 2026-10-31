"""SQLite connection management and versioned migrations.

One process, one writer. WAL mode allows concurrent readers; every write uses
``BEGIN IMMEDIATE`` so budget and idempotency reservations are serialized.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import cast

SCHEMA_VERSION = 2

_MIGRATION_1 = """
CREATE TABLE IF NOT EXISTS engagements (
    engagement_id TEXT PRIMARY KEY,
    mode TEXT NOT NULL,
    state TEXT NOT NULL,
    program_id TEXT,
    scope_id TEXT,
    scope_version INTEGER NOT NULL DEFAULT 0,
    policy_version TEXT NOT NULL DEFAULT 'unsealed',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    budget_limits_json TEXT NOT NULL,
    record_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_engagements_state ON engagements(state);

CREATE TABLE IF NOT EXISTS scopes (
    scope_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    content_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    approved_at TEXT NOT NULL,
    record_json TEXT NOT NULL,
    UNIQUE(engagement_id, version)
);
CREATE INDEX IF NOT EXISTS idx_scopes_engagement ON scopes(engagement_id, version DESC);

CREATE TABLE IF NOT EXISTS targets (
    target_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    host TEXT NOT NULL,
    scheme TEXT NOT NULL,
    port INTEGER NOT NULL,
    base_url TEXT NOT NULL,
    in_scope INTEGER NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    record_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_targets_engagement ON targets(engagement_id);
CREATE INDEX IF NOT EXISTS idx_targets_host ON targets(engagement_id, host);

CREATE TABLE IF NOT EXISTS tool_findings (
    finding_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    confidence TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    record_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_engagement ON tool_findings(engagement_id, observed_at);

CREATE TABLE IF NOT EXISTS hypotheses (
    hypothesis_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    bug_class_id TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    record_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hypotheses_engagement ON hypotheses(engagement_id, created_at);

CREATE TABLE IF NOT EXISTS decisions (
    decision_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    action TEXT NOT NULL,
    created_at TEXT NOT NULL,
    record_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_decisions_engagement ON decisions(engagement_id, created_at);

CREATE TABLE IF NOT EXISTS attempts (
    attempt_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    record_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts_engagement ON attempts(engagement_id, started_at);

CREATE TABLE IF NOT EXISTS validated_findings (
    finding_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    bug_class_id TEXT NOT NULL,
    status TEXT NOT NULL,
    dedup_fingerprint TEXT NOT NULL,
    human_review_status TEXT NOT NULL,
    validated_at TEXT NOT NULL,
    record_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_validated_engagement ON validated_findings(engagement_id, validated_at);
CREATE INDEX IF NOT EXISTS idx_validated_fingerprint ON validated_findings(engagement_id, dedup_fingerprint);

CREATE TABLE IF NOT EXISTS reviews (
    review_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    decision TEXT NOT NULL,
    reviewed_at TEXT NOT NULL,
    record_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reviews_finding ON reviews(finding_id, reviewed_at);

CREATE TABLE IF NOT EXISTS reports (
    report_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    status TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    record_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_engagement ON reports(engagement_id, generated_at);

CREATE TABLE IF NOT EXISTS approval_requests (
    approval_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    action_fingerprint TEXT NOT NULL,
    scope_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    record_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_approval_requests_engagement ON approval_requests(engagement_id, status);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    action_fingerprint TEXT NOT NULL,
    scope_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    approved_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    record_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_approvals_engagement ON approvals(engagement_id, approved_at);

CREATE TABLE IF NOT EXISTS action_ledger (
    idempotency_key TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    engagement_id TEXT NOT NULL,
    action_fingerprint TEXT NOT NULL,
    status TEXT NOT NULL,
    reserved_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    result_ref TEXT,
    error_code TEXT,
    record_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ledger_engagement ON action_ledger(engagement_id, updated_at);

CREATE TABLE IF NOT EXISTS budget_usage (
    engagement_id TEXT PRIMARY KEY,
    actions_used INTEGER NOT NULL DEFAULT 0,
    model_calls_used INTEGER NOT NULL DEFAULT 0,
    tokens_used INTEGER NOT NULL DEFAULT 0,
    cost_usd_used REAL NOT NULL DEFAULT 0,
    wall_clock_seconds_used INTEGER NOT NULL DEFAULT 0,
    requests_total INTEGER NOT NULL DEFAULT 0,
    window_started_at TEXT NOT NULL,
    started_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS host_rate_windows (
    engagement_id TEXT NOT NULL,
    host TEXT NOT NULL,
    window_started_at TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (engagement_id, host)
);

CREATE TABLE IF NOT EXISTS budget_reservations (
    reservation_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    host TEXT,
    requests INTEGER NOT NULL DEFAULT 0,
    actions INTEGER NOT NULL DEFAULT 0,
    model_calls INTEGER NOT NULL DEFAULT 0,
    tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd REAL NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    settled_at TEXT,
    record_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reservations_engagement ON budget_reservations(engagement_id, created_at);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id TEXT PRIMARY KEY,
    chain_key TEXT NOT NULL,
    engagement_id TEXT,
    occurred_at TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    record_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_chain ON audit_events(chain_key, occurred_at);

CREATE TABLE IF NOT EXISTS state_transitions (
    transition_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    record_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_transitions_engagement ON state_transitions(engagement_id, occurred_at);

CREATE TABLE IF NOT EXISTS checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    record_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_checkpoints_engagement ON checkpoints(engagement_id, created_at);

CREATE TABLE IF NOT EXISTS knowledge_units (
    unit_id TEXT PRIMARY KEY,
    tenant_scope TEXT NOT NULL,
    tier TEXT NOT NULL,
    domain TEXT,
    component TEXT,
    cwe_csv TEXT NOT NULL DEFAULT '',
    oracle_csv TEXT NOT NULL DEFAULT '',
    freshness_at TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    record_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_knowledge_tenant ON knowledge_units(tenant_scope, tier);

CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5(
    unit_id UNINDEXED,
    title,
    summary,
    tags
);

CREATE TABLE IF NOT EXISTS model_calls (
    call_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    checkpoint TEXT NOT NULL,
    started_at TEXT NOT NULL,
    record_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_model_calls_engagement ON model_calls(engagement_id, started_at);
"""

_MIGRATION_2 = """
CREATE TABLE IF NOT EXISTS action_requests (
    request_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    target_id TEXT,
    profile_id TEXT,
    requested_at TEXT NOT NULL,
    record_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_action_requests_engagement
    ON action_requests(engagement_id, requested_at);
"""

_MIGRATIONS: tuple[tuple[int, str], ...] = ((1, _MIGRATION_1), (2, _MIGRATION_2))


class Database:
    """Connection factory and migration runner."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=30.0,
            isolation_level=None,
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.execute("COMMIT")
        except BaseException:
            connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def execute(self, sql: str, params: tuple[object, ...] = ()) -> None:
        with self.transaction() as connection:
            connection.execute(sql, params)

    def query(self, sql: str, params: tuple[object, ...] = ()) -> list[sqlite3.Row]:
        connection = self.connect()
        try:
            return list(connection.execute(sql, params).fetchall())
        finally:
            connection.close()

    def query_one(self, sql: str, params: tuple[object, ...] = ()) -> sqlite3.Row | None:
        connection = self.connect()
        try:
            return cast(sqlite3.Row | None, connection.execute(sql, params).fetchone())
        finally:
            connection.close()

    def migrate(self) -> int:
        current = int(self.query_one("PRAGMA user_version")[0])  # type: ignore[index]
        for version, script in _MIGRATIONS:
            if version <= current:
                continue
            with self.transaction() as connection:
                for statement in _split_statements(script):
                    connection.execute(statement)
                connection.execute(f"PRAGMA user_version = {version}")
            current = version
        return current

    def health(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "schema_version": int(self.query_one("PRAGMA user_version")[0]),  # type: ignore[index]
            "journal_mode": str(self.query_one("PRAGMA journal_mode")[0]),  # type: ignore[index]
            "integrity": str(self.query_one("PRAGMA integrity_check")[0]),  # type: ignore[index]
        }


def _split_statements(script: str) -> list[str]:
    statements: list[str] = []
    buffer: list[str] = []
    for line in script.splitlines():
        stripped = line.strip()
        if stripped.startswith("--") or not stripped:
            continue
        buffer.append(line)
        if stripped.endswith(";"):
            statement = "\n".join(buffer).strip()
            if statement:
                statements.append(statement[:-1])
            buffer = []
    if buffer:
        statements.append("\n".join(buffer).strip())
    return statements
