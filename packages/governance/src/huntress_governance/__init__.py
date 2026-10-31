"""Huntress governance: scope, policy, approvals, budgets, and signing."""

from .approval import ApprovalCheck, ApprovalService
from .budget import BudgetManager, BudgetStore, InMemoryBudgetStore
from .errors import (
    ApprovalInvalid,
    BudgetExceeded,
    GovernanceError,
    HuntressError,
    IdempotencyConflict,
    PolicyDenied,
    ScopeCompileError,
    ScopeSealError,
)
from .gateway import PolicyGateway, budget_snapshot_for
from .hashing import (
    approval_content_hash,
    decision_content_hash,
    load_or_create_signing_key,
    scope_content_hash,
    sign,
    stable_digest,
    verify_approval_seal,
    verify_scope_seal,
    verify_signature,
)
from .ports import InMemoryApprovals, InMemoryLedger, LedgerStore
from .scope import ScopeCheck, ScopeCompiler, ScopeGuard, scope_fingerprint

__all__ = [
    "ApprovalCheck",
    "ApprovalInvalid",
    "ApprovalService",
    "BudgetExceeded",
    "BudgetManager",
    "BudgetStore",
    "GovernanceError",
    "HuntressError",
    "IdempotencyConflict",
    "InMemoryApprovals",
    "InMemoryBudgetStore",
    "InMemoryLedger",
    "LedgerStore",
    "PolicyDenied",
    "PolicyGateway",
    "ScopeCheck",
    "ScopeCompileError",
    "ScopeCompiler",
    "ScopeGuard",
    "ScopeSealError",
    "approval_content_hash",
    "budget_snapshot_for",
    "decision_content_hash",
    "load_or_create_signing_key",
    "scope_content_hash",
    "scope_fingerprint",
    "sign",
    "stable_digest",
    "verify_approval_seal",
    "verify_scope_seal",
    "verify_signature",
]
