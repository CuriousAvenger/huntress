"""Deterministic policy errors. These are control-flow, not prose."""

from __future__ import annotations

from huntress_contracts import ReasonCode


class HuntressError(Exception):
    """Base error for the application."""


class GovernanceError(HuntressError):
    """Base error for governance failures."""


class ScopeSealError(GovernanceError):
    """The sealed scope failed integrity verification."""


class ScopeCompileError(GovernanceError):
    """The draft scope is ambiguous, contradictory, or unsafe to approve."""


class PolicyDenied(GovernanceError):
    """A policy decision denied an action. Carries a stable reason code."""

    def __init__(self, reason_code: ReasonCode, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class BudgetExceeded(GovernanceError):
    """A transactional budget or rate reservation could not be made."""

    def __init__(self, message: str, *, reason_code: ReasonCode = ReasonCode.DENIED_BUDGET_EXHAUSTED) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class IdempotencyConflict(GovernanceError):
    """The idempotency key is already reserved or completed."""


class ApprovalInvalid(GovernanceError):
    """An approval is missing, expired, or bound to different content."""
