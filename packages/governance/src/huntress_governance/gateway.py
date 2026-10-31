"""The deterministic policy gateway.

Every executable action passes through ``PolicyGateway.evaluate`` immediately
before execution. The gateway never reads model prose and never accepts a
model-supplied target, command, budget, or scope. It composes:

    sealed scope + derived target + reviewed profile + approval + budget + ledger

A single denial is final for that request. A new request requires a new
decision and, when applicable, a new human approval.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from huntress_contracts import (
    ActionKind,
    ActionRequest,
    ApprovalRecord,
    BudgetSnapshot,
    Engagement,
    EngagementState,
    HttpMethod,
    PolicyDecision,
    ReasonCode,
    RiskClass,
    ScopeDocument,
    TargetRecord,
    ToolProfile,
    ensure_utc,
    new_id,
    risk_rank,
    utc_now,
)

from .approval import ApprovalService
from .budget import BudgetManager
from .hashing import decision_content_hash
from .ports import LedgerStore
from .scope import ScopeGuard

_ACTIVE_EXECUTION_STATES = frozenset(
    {
        EngagementState.READY,
        EngagementState.RECON,
        EngagementState.ANALYSIS,
        EngagementState.ACTION_PENDING,
        EngagementState.WAITING_FOR_APPROVAL,
        # The controller persists EXECUTING before invoking the executor so a
        # crash cannot lose the fact that an action was in flight. The
        # executor's mandatory recheck must therefore accept that state.
        EngagementState.EXECUTING,
    }
)
_TERMINAL_STATES = frozenset(
    {
        EngagementState.CLOSED,
        EngagementState.CANCELLED,
        EngagementState.FAILED,
        EngagementState.BLOCKED,
    }
)
_POLICY_VERSION = "huntress-policy/1.0"
_DECISION_TTL_SECONDS = 300


class PolicyGateway:
    """Single authority for allow/deny decisions."""

    def __init__(
        self,
        *,
        budget: BudgetManager,
        ledger: LedgerStore,
        scope_guard: ScopeGuard | None = None,
        approval_service: ApprovalService | None = None,
    ) -> None:
        self._budget = budget
        self._ledger = ledger
        self._scope_guard = scope_guard or ScopeGuard()
        self._approvals = approval_service or ApprovalService()

    def evaluate(
        self,
        *,
        request: ActionRequest,
        engagement: Engagement,
        scope: ScopeDocument,
        target: TargetRecord | None,
        profile: ToolProfile | None,
        signing_key: bytes,
        approval: ApprovalRecord | None = None,
        now: datetime | None = None,
    ) -> PolicyDecision:
        return self._evaluate(
            request=request,
            engagement=engagement,
            scope=scope,
            target=target,
            profile=profile,
            signing_key=signing_key,
            approval=approval,
            now=now,
            check_ledger=True,
            check_budget=True,
        )

    def recheck(
        self,
        *,
        request: ActionRequest,
        engagement: Engagement,
        scope: ScopeDocument,
        target: TargetRecord | None,
        profile: ToolProfile | None,
        signing_key: bytes,
        approval: ApprovalRecord | None = None,
        now: datetime | None = None,
    ) -> PolicyDecision:
        """Revalidate authorization immediately before execution.

        Budget and idempotency are intentionally excluded: the execution
        service has already reserved both. Every other gate is recomputed from
        the current records, including the scope seal, testing window, target
        match, profile policy, approval, and engagement state.
        """

        return self._evaluate(
            request=request,
            engagement=engagement,
            scope=scope,
            target=target,
            profile=profile,
            signing_key=signing_key,
            approval=approval,
            now=now,
            check_ledger=False,
            check_budget=False,
        )

    def _evaluate(
        self,
        *,
        request: ActionRequest,
        engagement: Engagement,
        scope: ScopeDocument,
        target: TargetRecord | None,
        profile: ToolProfile | None,
        signing_key: bytes,
        approval: ApprovalRecord | None,
        now: datetime | None,
        check_ledger: bool,
        check_budget: bool,
    ) -> PolicyDecision:
        moment = ensure_utc(now) if now is not None else utc_now()
        snapshot = self._budget.snapshot(engagement.engagement_id, engagement.budget_limits, moment)
        policy_version = self._policy_version(scope)
        expires_at = self._expiry(scope, moment)

        def decide(
            allowed: bool,
            code: ReasonCode,
            reasons: tuple[str, ...],
            *,
            requires_approval: bool = False,
            approval_id: str | None = None,
        ) -> PolicyDecision:
            decision = PolicyDecision(
                decision_id=new_id("pol"),
                request_id=request.request_id,
                engagement_id=engagement.engagement_id,
                allowed=allowed,
                reason_code=code,
                reasons=reasons,
                policy_version=policy_version,
                scope_hash=scope.content_hash,
                action_fingerprint=request.action_fingerprint(),
                budget_snapshot=snapshot,
                requires_approval=requires_approval,
                approval_id=approval_id,
                decided_at=moment,
                expires_at=expires_at,
                decision_hash="",
            )
            return decision.model_copy(update={"decision_hash": decision_content_hash(decision)})

        if engagement.engagement_id != request.engagement_id:
            return decide(
                False,
                ReasonCode.DENIED_UNKNOWN_ENGAGEMENT,
                ("request engagement does not match the loaded engagement",),
            )
        if engagement.state in _TERMINAL_STATES:
            return decide(
                False,
                ReasonCode.DENIED_ENGAGEMENT_STATE,
                (f"engagement is terminal: {engagement.state}",),
            )
        if engagement.state not in _ACTIVE_EXECUTION_STATES:
            return decide(
                False,
                ReasonCode.DENIED_ENGAGEMENT_STATE,
                (f"engagement state {engagement.state} does not permit actions",),
            )
        if scope.testing_window.ends_at <= moment:
            return decide(
                False,
                ReasonCode.DENIED_SCOPE_EXPIRED,
                ("testing window has ended",),
            )
        if request.action is not ActionKind.RUN_APPROVED_PROFILE:
            return decide(True, ReasonCode.ALLOWED, ("non-executing action",))

        if target is None:
            return decide(False, ReasonCode.DENIED_TARGET_NOT_FOUND, ("target not found",))
        if profile is None:
            return decide(False, ReasonCode.DENIED_PROFILE_UNKNOWN, ("profile not found",))
        if profile.profile_id not in scope.allowed_profiles:
            return decide(
                False,
                ReasonCode.DENIED_PROFILE_NOT_ALLOWED,
                (f"profile {profile.profile_id} is not in the approved scope",),
            )
        if target.asset_kind not in profile.supported_asset_kinds:
            return decide(
                False,
                ReasonCode.DENIED_PROFILE_ASSET_KIND,
                (f"profile does not support asset kind {target.asset_kind}",),
            )
        if risk_rank(profile.risk_class) > risk_rank(scope.roe.max_risk_class):
            return decide(
                False,
                ReasonCode.DENIED_RISK_NOT_ALLOWED,
                (f"profile risk {profile.risk_class} exceeds ROE {scope.roe.max_risk_class}",),
            )
        if profile.side_effect_class not in scope.roe.allowed_side_effects:
            return decide(
                False,
                ReasonCode.DENIED_SIDE_EFFECT_NOT_ALLOWED,
                (f"side effect {profile.side_effect_class} is not allowed by ROE",),
            )
        if profile.risk_class is RiskClass.EXPLOIT_LIKE and not scope.roe.allow_exploit_like:
            return decide(
                False,
                ReasonCode.DENIED_EXPLOIT_NOT_AUTHORIZED,
                ("exploit-like testing is not authorized for this program",),
            )
        if "availability" in profile.tags:
            return decide(
                False,
                ReasonCode.DENIED_AVAILABILITY_DISABLED,
                ("availability testing is disabled",),
            )
        if not profile.allowed_methods:
            return decide(
                False,
                ReasonCode.DENIED_INVALID_REQUEST,
                ("profile declares no allowed methods",),
            )

        methods: tuple[HttpMethod, ...] = profile.allowed_methods
        for method in methods:
            scope_check = self._scope_guard.check_target(
                engagement=engagement,
                scope=scope,
                target=target,
                method=method,
                now=moment,
                signing_key=signing_key,
            )
            if not scope_check.allowed:
                return decide(False, scope_check.reason_code, scope_check.reasons)

        if check_ledger:
            existing = self._ledger.get(request.idempotency_key)
            if existing is not None:
                return decide(
                    False,
                    ReasonCode.DENIED_IDEMPOTENT_REPLAY,
                    (
                        f"idempotency key already exists in state {existing.status}; "
                        "retrieve the prior result instead of re-executing",
                    ),
                )

        approval_required = profile.requires_approval and profile.profile_id not in scope.preapproved_profiles
        validated_approval_id: str | None = None
        if approval_required:
            if approval is None:
                return decide(
                    False,
                    ReasonCode.DENIED_APPROVAL_REQUIRED,
                    (f"profile {profile.profile_id} requires explicit human approval",),
                    requires_approval=True,
                )
            approval_check = self._approvals.verify(
                approval=approval,
                request=request,
                scope=scope,
                signing_key=signing_key,
                now=moment,
            )
            if not approval_check.valid:
                return decide(
                    False,
                    ReasonCode.DENIED_APPROVAL_INVALID,
                    (approval_check.reason,),
                    requires_approval=True,
                )
            validated_approval_id = approval.approval_id

        if check_budget:
            code, budget_reasons = self._budget.check(
                snapshot,
                host=target.host,
                requests=profile.max_requests_per_run,
                actions=1,
            )
            if code is not None:
                return decide(False, code, budget_reasons)

        return decide(
            True,
            ReasonCode.ALLOWED,
            ("scope, target, profile, approval, budget, rate, and idempotency checks passed",),
            requires_approval=approval_required,
            approval_id=validated_approval_id,
        )

    @staticmethod
    def _policy_version(scope: ScopeDocument) -> str:
        return f"{_POLICY_VERSION}:scope-v{scope.version}:{scope.content_hash[:16]}"

    @staticmethod
    def _expiry(scope: ScopeDocument, now: datetime) -> datetime:
        candidate = now + timedelta(seconds=_DECISION_TTL_SECONDS)
        return min(candidate, scope.testing_window.ends_at)


def budget_snapshot_for(manager: BudgetManager, engagement: Engagement, now: datetime) -> BudgetSnapshot:
    """Convenience for CLI status output."""

    return manager.snapshot(engagement.engagement_id, engagement.budget_limits, now)
