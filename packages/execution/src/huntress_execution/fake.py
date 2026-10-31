"""Deterministic fake execution backend and in-memory test doubles.

The fake backend performs no network or container access. It exists for unit,
policy, replay, and CI tests, and is never selected implicitly for an Exegol
profile in production auto-detection.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field

from huntress_contracts import (
    ActionLedgerEntry,
    TestAttempt,
    ToolFinding,
    ToolRunStatus,
)

from .models import BackendContext, BackendOutput


@dataclass(frozen=True, slots=True)
class FakeResponse:
    """A canned backend response keyed by profile ID."""

    status: ToolRunStatus = ToolRunStatus.SUCCEEDED
    exit_code: int | None = 0
    stdout: bytes = b""
    stderr: bytes = b""
    request_count: int = 1
    findings: tuple[ToolFinding, ...] = ()
    artifact_refs: tuple[str, ...] = ()
    output_truncated: bool = False
    timed_out: bool = False
    error_code: str | None = None
    error_message: str = ""


class FakeExecutionBackend:
    """Deterministic executor for tests and offline evaluation."""

    name = "fake"

    def __init__(
        self,
        responses: Mapping[str, FakeResponse] | None = None,
        *,
        handler: Callable[[BackendContext], BackendOutput] | None = None,
    ) -> None:
        self._responses = dict(responses or {})
        self._handler = handler

    def execute(self, context: BackendContext) -> BackendOutput:
        if self._handler is not None:
            return self._handler(context)
        response = self._responses.get(context.profile.profile_id)
        if response is None:
            payload = {
                "backend": self.name,
                "profile_id": context.profile.profile_id,
                "profile_version": context.profile.version,
                "target_id": context.target.target_id,
                "host": context.target.host,
                "base_url": context.target.base_url,
                "simulated": True,
            }
            stdout = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
            return BackendOutput(
                status=ToolRunStatus.SUCCEEDED,
                exit_code=0,
                stdout=stdout,
                request_count=1,
                backend=self.name,
            )
        return BackendOutput(
            status=response.status,
            exit_code=response.exit_code,
            stdout=response.stdout,
            stderr=response.stderr,
            request_count=response.request_count,
            findings=response.findings,
            artifact_refs=response.artifact_refs,
            output_truncated=response.output_truncated,
            timed_out=response.timed_out or response.status is ToolRunStatus.TIMEOUT,
            error_code=response.error_code,
            error_message=response.error_message,
            backend=self.name,
        )


class InMemoryExecutionLedger:
    """Atomic insert-if-absent ledger double for unit tests."""

    def __init__(self) -> None:
        self.entries: dict[str, ActionLedgerEntry] = {}

    def get(self, idempotency_key: str) -> ActionLedgerEntry | None:
        return self.entries.get(idempotency_key)

    def reserve(self, entry: ActionLedgerEntry) -> bool:
        if entry.idempotency_key in self.entries:
            return False
        self.entries[entry.idempotency_key] = entry
        return True

    def update(self, entry: ActionLedgerEntry) -> None:
        self.entries[entry.idempotency_key] = entry

    def all(self) -> tuple[ActionLedgerEntry, ...]:
        return tuple(self.entries.values())


@dataclass
class InMemoryAttemptStore:
    attempts: list[TestAttempt] = field(default_factory=list)

    def save(self, attempt: TestAttempt) -> TestAttempt:
        self.attempts.append(attempt)
        return attempt


@dataclass
class InMemoryFindingStore:
    findings: list[ToolFinding] = field(default_factory=list)

    def save_many(self, findings: Iterable[ToolFinding]) -> int:
        rows = list(findings)
        self.findings.extend(rows)
        return len(rows)
