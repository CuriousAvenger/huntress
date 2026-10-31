"""Persistence ports consumed by governance.

Defining these as protocols keeps governance free of SQLite and lets tests use
deterministic in-memory doubles.
"""

from __future__ import annotations

from typing import Protocol

from huntress_contracts import ActionLedgerEntry, ApprovalRecord, BudgetLimits, BudgetReservation


class LedgerStore(Protocol):
    def get(self, idempotency_key: str) -> ActionLedgerEntry | None: ...


class ApprovalStore(Protocol):
    def get_approval(self, approval_id: str) -> ApprovalRecord | None: ...


class ScopeStore(Protocol):
    def get_latest_scope(self, engagement_id: str) -> object | None: ...


class BudgetReservationStore(Protocol):
    def reserve(
        self,
        engagement_id: str,
        limits: BudgetLimits,
        reservation: BudgetReservation,
    ) -> BudgetReservation: ...


class InMemoryLedger:
    """Minimal ledger double for policy tests."""

    def __init__(self) -> None:
        self.entries: dict[str, ActionLedgerEntry] = {}

    def get(self, idempotency_key: str) -> ActionLedgerEntry | None:
        return self.entries.get(idempotency_key)

    def put(self, entry: ActionLedgerEntry) -> None:
        self.entries[entry.idempotency_key] = entry


class InMemoryApprovals:
    """Minimal approval store double for policy tests."""

    def __init__(self) -> None:
        self.records: dict[str, ApprovalRecord] = {}

    def get_approval(self, approval_id: str) -> ApprovalRecord | None:
        return self.records.get(approval_id)

    def put(self, record: ApprovalRecord) -> None:
        self.records[record.approval_id] = record
