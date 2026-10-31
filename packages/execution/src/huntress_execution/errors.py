"""Typed execution errors.

Pre-execution denials are exceptions because no side effect has occurred and
the caller must not persist a fabricated attempt. Failures after a backend has
been invoked are represented as a ``ToolRunResult`` with a non-success status.
"""

from __future__ import annotations

from huntress_contracts import ActionLedgerEntry, ReasonCode


class ExecutionError(Exception):
    """Base class for execution failures."""


class ExecutionDenied(ExecutionError):
    """Authorization or lifecycle check failed before any side effect."""

    def __init__(self, reason_code: ReasonCode, reasons: tuple[str, ...]) -> None:
        self.reason_code = reason_code
        self.reasons = reasons
        super().__init__("; ".join(reasons) or reason_code.value)


class IdempotentReplay(ExecutionError):
    """The idempotency key is already owned by a previous attempt."""

    def __init__(self, entry: ActionLedgerEntry) -> None:
        self.entry = entry
        super().__init__(
            f"idempotency key {entry.idempotency_key!r} already exists in state "
            f"{entry.status.value}"
        )


class ProfileUnknown(ExecutionError):
    """The requested profile is not in the reviewed registry."""


class BackendUnavailable(ExecutionError):
    """No configured backend can execute the requested profile."""


class BackendContractError(ExecutionError):
    """A backend returned data that violates the execution boundary."""
