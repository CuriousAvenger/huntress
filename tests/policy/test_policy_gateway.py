"""Negative and positive policy-gateway invariants.

These tests exercise the deterministic authority layer without a database,
network, execution backend, or model. Every denial is asserted by its stable
reason code, not by prose.
"""

from __future__ import annotations

from datetime import timedelta

from huntress_contracts import (
    ActionKind,
    ActionLedgerEntry,
    ActionRequest,
    BudgetLimits,
    BudgetUsage,
    EngagementState,
    LedgerStatus,
    ReasonCode,
    RiskClass,
    utc_now,
)
from huntress_execution import ALL_PROFILES
from huntress_governance import (
    ApprovalService,
    BudgetManager,
    InMemoryBudgetStore,
    InMemoryLedger,
    PolicyGateway,
    ScopeCompiler,
)
from tests.conftest import make_scope_draft
from tests.helpers import make_engagement, make_target

KEY = b"k" * 32
LOW = ("http.baseline", "http.security_headers", "http.exposed_files", "http.cors")
ACTIVE = ("http.open_redirect", "http.reflected_marker", "http.error_based_sqli")


def _scope(
    *,
    profiles: tuple[str, ...] = LOW,
    preapproved: tuple[str, ...] = LOW,
    max_risk: RiskClass = RiskClass.LOW,
    hours: int = 2,
):
    engagement = make_engagement()
    draft = make_scope_draft(
        engagement_id=engagement.engagement_id,
        url="http://127.0.0.1:8080",
        profiles=profiles,
        preapproved=preapproved,
        max_risk=max_risk,
        hours=hours,
    )
    scope = ScopeCompiler(KEY).compile(
        draft,
        profiles=ALL_PROFILES,
        approved_by="Approver",
        scope_id="scope_policy000001",
    )
    target = make_target(
        engagement.engagement_id,
        "http://127.0.0.1:8080",
        asset_id=scope.assets[0].asset_id,
    )
    return engagement, scope, target


def _request(
    *,
    engagement_id: str,
    target_id: str,
    profile_id: str,
    evidence_ids: tuple[str, ...] = (),
    idempotency_key: str = "act:policy000001",
) -> ActionRequest:
    return ActionRequest(
        request_id="req_policy000001",
        engagement_id=engagement_id,
        action=ActionKind.RUN_APPROVED_PROFILE,
        target_id=target_id,
        profile_id=profile_id,
        evidence_ids=evidence_ids,
        idempotency_key=idempotency_key,
        requested_by="pytest",
        requested_at=utc_now(),
    )


def _gateway(
    *,
    ledger: InMemoryLedger | None = None,
    budget_store: InMemoryBudgetStore | None = None,
) -> PolicyGateway:
    return PolicyGateway(
        budget=BudgetManager(budget_store or InMemoryBudgetStore()),
        ledger=ledger or InMemoryLedger(),
        approval_service=ApprovalService(),
    )


def _evaluate(gateway: PolicyGateway, *, request, engagement, scope, target, profile, **kwargs):
    from huntress_execution import DEFAULT_PROFILE_REGISTRY

    return gateway.evaluate(
        request=request,
        engagement=engagement,
        scope=scope,
        target=target,
        profile=DEFAULT_PROFILE_REGISTRY.require(profile),
        signing_key=KEY,
        **kwargs,
    )


def test_preauthorized_low_risk_profile_is_allowed() -> None:
    engagement, scope, target = _scope()
    request = _request(
        engagement_id=engagement.engagement_id,
        target_id=target.target_id,
        profile_id="http.baseline",
    )
    decision = _evaluate(
        _gateway(),
        request=request,
        engagement=engagement,
        scope=scope,
        target=target,
        profile="http.baseline",
    )
    assert decision.allowed
    assert decision.reason_code is ReasonCode.ALLOWED
    assert not decision.requires_approval
    assert decision.action_fingerprint == request.action_fingerprint()


def test_active_profile_requires_a_human_approval() -> None:
    engagement, scope, target = _scope(
        profiles=(*LOW, *ACTIVE), preapproved=LOW, max_risk=RiskClass.ACTIVE
    )
    request = _request(
        engagement_id=engagement.engagement_id,
        target_id=target.target_id,
        profile_id="http.open_redirect",
    )
    decision = _evaluate(
        _gateway(),
        request=request,
        engagement=engagement,
        scope=scope,
        target=target,
        profile="http.open_redirect",
    )
    assert not decision.allowed
    assert decision.reason_code is ReasonCode.DENIED_APPROVAL_REQUIRED
    assert decision.requires_approval


def test_valid_approval_is_bound_to_the_exact_action_and_scope() -> None:
    engagement, scope, target = _scope(
        profiles=(*LOW, *ACTIVE), preapproved=LOW, max_risk=RiskClass.ACTIVE
    )
    approvals = ApprovalService()
    request = _request(
        engagement_id=engagement.engagement_id,
        target_id=target.target_id,
        profile_id="http.open_redirect",
    )
    approval_request = approvals.create_request(
        request=request,
        scope=scope,
        requested_by="pytest",
        reason="pytest approval",
    )
    record = approvals.approve(
        approval_request=approval_request,
        scope=scope,
        approved_by="Reviewer One",
        signing_key=KEY,
    )
    decision = _evaluate(
        _gateway(),
        request=request,
        engagement=engagement,
        scope=scope,
        target=target,
        profile="http.open_redirect",
        approval=record,
    )
    assert decision.allowed
    assert decision.requires_approval
    assert decision.approval_id == record.approval_id


def test_approval_does_not_transfer_to_another_profile_or_evidence_set() -> None:
    engagement, scope, target = _scope(
        profiles=(*LOW, *ACTIVE), preapproved=LOW, max_risk=RiskClass.ACTIVE
    )
    approvals = ApprovalService()
    original = _request(
        engagement_id=engagement.engagement_id,
        target_id=target.target_id,
        profile_id="http.open_redirect",
    )
    approval_request = approvals.create_request(
        request=original,
        scope=scope,
        requested_by="pytest",
        reason="pytest approval",
    )
    record = approvals.approve(
        approval_request=approval_request,
        scope=scope,
        approved_by="Reviewer One",
        signing_key=KEY,
    )

    different_profile = _request(
        engagement_id=engagement.engagement_id,
        target_id=target.target_id,
        profile_id="http.reflected_marker",
    )
    denied_profile = _evaluate(
        _gateway(),
        request=different_profile,
        engagement=engagement,
        scope=scope,
        target=target,
        profile="http.reflected_marker",
        approval=record,
    )
    assert denied_profile.reason_code is ReasonCode.DENIED_APPROVAL_INVALID

    different_evidence = _request(
        engagement_id=engagement.engagement_id,
        target_id=target.target_id,
        profile_id="http.open_redirect",
        evidence_ids=("tf_policy000001",),
    )
    denied_evidence = _evaluate(
        _gateway(),
        request=different_evidence,
        engagement=engagement,
        scope=scope,
        target=target,
        profile="http.open_redirect",
        approval=record,
    )
    assert denied_evidence.reason_code is ReasonCode.DENIED_APPROVAL_INVALID


def test_expired_and_tampered_approvals_are_rejected() -> None:
    engagement, scope, target = _scope(
        profiles=(*LOW, *ACTIVE), preapproved=LOW, max_risk=RiskClass.ACTIVE
    )
    approvals = ApprovalService()
    now = utc_now()
    request = _request(
        engagement_id=engagement.engagement_id,
        target_id=target.target_id,
        profile_id="http.open_redirect",
    )
    approval_request = approvals.create_request(
        request=request,
        scope=scope,
        requested_by="pytest",
        reason="pytest approval",
        now=now,
    )
    record = approvals.approve(
        approval_request=approval_request,
        scope=scope,
        approved_by="Reviewer One",
        signing_key=KEY,
        ttl_seconds=60,
        now=now,
    )

    expired = _evaluate(
        _gateway(),
        request=request,
        engagement=engagement,
        scope=scope,
        target=target,
        profile="http.open_redirect",
        approval=record,
        now=now + timedelta(seconds=61),
    )
    assert expired.reason_code is ReasonCode.DENIED_APPROVAL_INVALID

    tampered = record.model_copy(update={"approved_by": "Mallory"})
    denied_tampered = _evaluate(
        _gateway(),
        request=request,
        engagement=engagement,
        scope=scope,
        target=target,
        profile="http.open_redirect",
        approval=tampered,
        now=now,
    )
    assert denied_tampered.reason_code is ReasonCode.DENIED_APPROVAL_INVALID


def test_scope_tampering_and_expired_windows_are_denied() -> None:
    engagement, scope, target = _scope(hours=1)
    request = _request(
        engagement_id=engagement.engagement_id,
        target_id=target.target_id,
        profile_id="http.baseline",
    )

    tampered_scope = scope.model_copy(update={"program_id": "attacker-program"})
    denied_integrity = _evaluate(
        _gateway(),
        request=request,
        engagement=engagement,
        scope=tampered_scope,
        target=target,
        profile="http.baseline",
    )
    assert denied_integrity.reason_code is ReasonCode.DENIED_SCOPE_INTEGRITY

    denied_expired = _evaluate(
        _gateway(),
        request=request,
        engagement=engagement,
        scope=scope,
        target=target,
        profile="http.baseline",
        now=utc_now() + timedelta(hours=2),
    )
    assert denied_expired.reason_code is ReasonCode.DENIED_SCOPE_EXPIRED


def test_terminal_engagement_state_is_denied() -> None:
    engagement, scope, target = _scope()
    request = _request(
        engagement_id=engagement.engagement_id,
        target_id=target.target_id,
        profile_id="http.baseline",
    )
    closed = engagement.model_copy(update={"state": EngagementState.CLOSED})
    decision = _evaluate(
        _gateway(), request=request, engagement=closed, scope=scope, target=target, profile="http.baseline"
    )
    assert decision.reason_code is ReasonCode.DENIED_ENGAGEMENT_STATE


def test_profile_outside_scope_is_denied_before_approval() -> None:
    engagement, scope, target = _scope()
    request = _request(
        engagement_id=engagement.engagement_id,
        target_id=target.target_id,
        profile_id="http.open_redirect",
    )
    decision = _evaluate(
        _gateway(),
        request=request,
        engagement=engagement,
        scope=scope,
        target=target,
        profile="http.open_redirect",
    )
    assert decision.reason_code is ReasonCode.DENIED_PROFILE_NOT_ALLOWED


class _ExhaustedBudgetStore(InMemoryBudgetStore):
    def get_usage(self, engagement_id: str) -> BudgetUsage:
        limits = BudgetLimits()
        return BudgetUsage(actions_used=limits.max_actions)


def test_exhausted_action_budget_is_denied() -> None:
    engagement, scope, target = _scope()
    request = _request(
        engagement_id=engagement.engagement_id,
        target_id=target.target_id,
        profile_id="http.baseline",
    )
    decision = _evaluate(
        _gateway(budget_store=_ExhaustedBudgetStore()),
        request=request,
        engagement=engagement,
        scope=scope,
        target=target,
        profile="http.baseline",
    )
    assert decision.reason_code is ReasonCode.DENIED_BUDGET_EXHAUSTED


def test_idempotency_key_cannot_be_reused() -> None:
    engagement, scope, target = _scope()
    request = _request(
        engagement_id=engagement.engagement_id,
        target_id=target.target_id,
        profile_id="http.baseline",
    )
    now = utc_now()
    ledger = InMemoryLedger()
    ledger.put(
        ActionLedgerEntry(
            idempotency_key=request.idempotency_key,
            request_id=request.request_id,
            engagement_id=engagement.engagement_id,
            action_fingerprint=request.action_fingerprint(),
            status=LedgerStatus.COMPLETED,
            reserved_at=now,
            updated_at=now,
        )
    )
    decision = _evaluate(
        _gateway(ledger=ledger),
        request=request,
        engagement=engagement,
        scope=scope,
        target=target,
        profile="http.baseline",
    )
    assert decision.reason_code is ReasonCode.DENIED_IDEMPOTENT_REPLAY


def test_recheck_skips_ledger_and_budget_but_keeps_authorization() -> None:
    engagement, scope, target = _scope()
    request = _request(
        engagement_id=engagement.engagement_id,
        target_id=target.target_id,
        profile_id="http.baseline",
    )
    from huntress_execution import DEFAULT_PROFILE_REGISTRY

    now = utc_now()
    ledger = InMemoryLedger()
    ledger.put(
        ActionLedgerEntry(
            idempotency_key=request.idempotency_key,
            request_id=request.request_id,
            engagement_id=engagement.engagement_id,
            action_fingerprint=request.action_fingerprint(),
            status=LedgerStatus.EXECUTING,
            reserved_at=now,
            updated_at=now,
        )
    )
    gateway = _gateway(ledger=ledger, budget_store=_ExhaustedBudgetStore())
    decision = gateway.recheck(
        request=request,
        engagement=engagement,
        scope=scope,
        target=target,
        profile=DEFAULT_PROFILE_REGISTRY.require("http.baseline"),
        signing_key=KEY,
        now=now,
    )
    assert decision.allowed

    denied = gateway.recheck(
        request=request,
        engagement=engagement,
        scope=scope.model_copy(update={"program_id": "tampered"}),
        target=target,
        profile=DEFAULT_PROFILE_REGISTRY.require("http.baseline"),
        signing_key=KEY,
        now=now,
    )
    assert denied.reason_code is ReasonCode.DENIED_SCOPE_INTEGRITY
