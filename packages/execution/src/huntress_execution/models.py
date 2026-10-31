"""Internal execution boundary objects and ports.

The model never sees these types. A backend receives a fully-resolved context
whose target, profile, scope, and authorization callback were assembled by the
controller and execution service.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from huntress_contracts import (
    ActionLedgerEntry,
    AuditEvent,
    BudgetReservation,
    Engagement,
    ExecutionRequest,
    HttpMethod,
    PolicyDecision,
    ScopeDocument,
    TargetRecord,
    TestAttempt,
    ToolFinding,
    ToolProfile,
    ToolRunResult,
    ToolRunStatus,
)


@dataclass(frozen=True, slots=True)
class BackendContext:
    """Everything a reviewed backend needs, with no model-supplied strings."""

    request: ExecutionRequest
    profile: ToolProfile
    engagement: Engagement
    target: TargetRecord
    scope: ScopeDocument
    authorize_url: Callable[[str, HttpMethod], bool]
    policy_version: str
    scope_hash: str
    now: datetime


@dataclass(frozen=True, slots=True)
class BackendOutput:
    """Raw backend output before artifact capture and persistence."""

    status: ToolRunStatus
    exit_code: int | None = None
    stdout: bytes = b""
    stderr: bytes = b""
    request_count: int = 0
    findings: tuple[ToolFinding, ...] = ()
    artifact_refs: tuple[str, ...] = ()
    output_truncated: bool = False
    timed_out: bool = False
    error_code: str | None = None
    error_message: str = ""
    backend: str = "fake"


@runtime_checkable
class ExecutionBackendPort(Protocol):
    """A fixed executor. Implementations are reviewed code, never model tools."""

    name: str

    def execute(self, context: BackendContext) -> BackendOutput: ...


class ExecutionLedger(Protocol):
    """Idempotency ledger with an atomic insert-if-absent reservation."""

    def get(self, idempotency_key: str) -> ActionLedgerEntry | None: ...

    def reserve(self, entry: ActionLedgerEntry) -> bool: ...

    def update(self, entry: ActionLedgerEntry) -> None: ...


class AttemptStore(Protocol):
    def save(self, attempt: TestAttempt) -> TestAttempt: ...


class FindingStore(Protocol):
    def save_many(self, findings: Iterable[ToolFinding]) -> int: ...


class AuditSink(Protocol):
    def append(self, event: AuditEvent) -> AuditEvent: ...


@dataclass(frozen=True, slots=True)
class ExecutionOutcome:
    """Durable result of one executed (or attempted) profile invocation."""

    request: ExecutionRequest
    decision: PolicyDecision
    run_result: ToolRunResult
    attempt: TestAttempt
    findings: tuple[ToolFinding, ...]
    ledger_entry: ActionLedgerEntry
    budget_reservation: BudgetReservation | None
    backend: str
