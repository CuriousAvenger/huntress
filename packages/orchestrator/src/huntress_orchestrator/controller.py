"""Durable engagement controller.

The controller owns lifecycle transitions and is the only application layer
that composes policy, execution, validation, review, reasoning, and reporting.
It never executes a model-supplied command or URL: actions reference reviewed
profile IDs and server-side target IDs, and the policy gateway is recomputed
immediately before every side effect.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import urlsplit

from huntress_contracts import (
    ActionKind,
    ActionRequest,
    Actor,
    ActorType,
    ApprovalRecord,
    ApprovalRequest,
    ApprovalStatus,
    AuditChainVerification,
    AuditEvent,
    BudgetSnapshot,
    Checkpoint,
    ContextPacket,
    ContextTask,
    DecisionSource,
    DuplicateStatus,
    Engagement,
    EngagementMode,
    EngagementState,
    EvidenceDigestItem,
    ExecutionRequest,
    GateStatus,
    HumanReviewStatus,
    InvestigationDecision,
    PolicyDecision,
    RetrievalQuery,
    ScopeDocument,
    ScopeStatus,
    SeverityBand,
    SideEffectClass,
    TargetRecord,
    TestAttempt,
    ToolFinding,
    ToolProfile,
    ValidatedFinding,
    ValidationStatus,
    VulnerabilityReport,
    ensure_utc,
    get_bug_class,
    new_id,
    sha256_hex,
    utc_now,
)
from huntress_execution import ExecutionDenied, ExecutionOutcome, IdempotentReplay, ProfileUnknown
from huntress_governance import HuntressError, verify_scope_seal
from huntress_reasoning import (
    ContextRequest,
    DecisionOutcome,
    RuleBasedPlanner,
    output_contract,
)
from huntress_reporting import ReportNotReady
from huntress_verification import (
    ReviewDenied,
    ReviewOutcome,
    SeverityInputs,
    ValidationOutcome,
    ValidationRequest,
)
from huntress_verification.reproduction import ReproductionEvidence

from .container import Container
from .state import StateMachine, can_transition

_SECRET_ASSIGNMENT = re.compile(
    r"(?im)^\s*[A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|APP_KEY|PRIVATE_KEY|"
    r"DATABASE_URL|DB_PASSWORD)[A-Z0-9_]*\s*=\s*\S+"
)
_GIT_HEAD = re.compile(r"[0-9a-f]{40}")


class ControllerError(HuntressError):
    """A workflow precondition failed."""


class EngagementNotFound(ControllerError):
    """The requested engagement does not exist."""


class ScopeNotReady(ControllerError):
    """The engagement has no sealed, approved scope."""


class ActionDenied(ControllerError):
    """The policy gateway refused an action that the controller tried to run."""

    def __init__(self, decision: PolicyDecision) -> None:
        self.decision = decision
        super().__init__(
            f"{decision.reason_code.value}: " + "; ".join(decision.reasons or ("denied",))
        )


@dataclass(frozen=True, slots=True)
class ActionPlan:
    """The result of requesting one action."""

    request: ActionRequest
    decision: PolicyDecision
    approval_request: ApprovalRequest | None = None
    outcome: ExecutionOutcome | None = None

    @property
    def executed(self) -> bool:
        return self.outcome is not None


@dataclass(frozen=True, slots=True)
class ApprovalOutcome:
    record: ApprovalRecord
    outcome: ExecutionOutcome | None = None


@dataclass(frozen=True, slots=True)
class ReasoningResult:
    packet: ContextPacket
    rendered: str
    decision: InvestigationDecision | None
    used_model: bool
    errors: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EngagementStatus:
    engagement: Engagement
    scope: ScopeDocument | None
    budget: BudgetSnapshot
    targets: tuple[TargetRecord, ...]
    attempts: tuple[TestAttempt, ...]
    tool_findings: tuple[ToolFinding, ...]
    validated_findings: tuple[ValidatedFinding, ...]
    pending_approvals: tuple[ApprovalRequest, ...]
    reports: tuple[VulnerabilityReport, ...]
    audit: AuditChainVerification


class Controller:
    """Durable, auditable workflow over the application container."""

    def __init__(self, container: Container, *, clock: object | None = None) -> None:
        self.container = container
        self.state_machine = StateMachine()
        self._clock = clock

    # -- clock --------------------------------------------------------------
    def _now(self) -> datetime:
        if callable(self._clock):
            value = self._clock()
            if isinstance(value, datetime):
                return ensure_utc(value)
        return utc_now()

    # -- audit and lifecycle ------------------------------------------------
    def _audit(
        self,
        *,
        engagement_id: str | None,
        actor_type: ActorType,
        actor_id: str,
        action: str,
        outcome: str,
        correlation_id: str,
        details: dict[str, str | int | float | bool] | None = None,
        policy_version: str | None = None,
        tool_profile: str | None = None,
        model_id: str | None = None,
    ) -> AuditEvent:
        event = AuditEvent(
            event_id=new_id("aud"),
            occurred_at=self._now(),
            engagement_id=engagement_id,
            actor=Actor(type=actor_type, id=actor_id[:200]),
            action=action[:120],
            outcome=outcome[:80],
            correlation_id=correlation_id[:120],
            policy_version=policy_version[:80] if policy_version else None,
            tool_profile=tool_profile[:120] if tool_profile else None,
            model_id=model_id[:200] if model_id else None,
            details=details or {},
        )
        return self.container.repos.audit.append(event)

    def _transition(
        self,
        engagement: Engagement,
        to_state: EngagementState,
        *,
        reason: str,
        actor_type: ActorType = ActorType.SYSTEM,
        actor_id: str = "controller",
        correlation_id: str | None = None,
    ) -> Engagement:
        updated, transition = self.state_machine.transition(
            engagement,
            to_state,
            reason=reason,
            actor_type=actor_type,
            actor_id=actor_id,
            correlation_id=correlation_id,
            now=self._now(),
        )
        self.container.repos.engagements.save(updated)
        self.container.repos.transitions.save(transition)
        checkpoint = self.state_machine.checkpoint(
            updated,
            correlation_id=transition.correlation_id,
            payload={
                "from_state": transition.from_state.value,
                "to_state": transition.to_state.value,
            },
            note=reason,
            now=transition.occurred_at,
        )
        self.container.repos.checkpoints.save(checkpoint)
        self._audit(
            engagement_id=updated.engagement_id,
            actor_type=actor_type,
            actor_id=actor_id,
            action="state_transition",
            outcome=to_state.value,
            correlation_id=transition.correlation_id,
            details={
                "from_state": transition.from_state.value,
                "to_state": transition.to_state.value,
                "transition_id": transition.transition_id,
            },
        )
        return updated

    def _reload(self, engagement_id: str) -> Engagement:
        engagement = self.container.repos.engagements.get(engagement_id)
        if engagement is None:
            raise EngagementNotFound(f"unknown engagement: {engagement_id}")
        return engagement

    def _prepare_for_action(self, engagement: Engagement) -> Engagement:
        if engagement.state in {
            EngagementState.READY,
            EngagementState.RECON,
            EngagementState.ANALYSIS,
            EngagementState.ACTION_PENDING,
            EngagementState.WAITING_FOR_APPROVAL,
        }:
            return engagement
        if engagement.state in {
            EngagementState.HUMAN_REVIEW,
            EngagementState.VALIDATING,
            EngagementState.REPORT_DRAFT,
        }:
            return self._transition(
                engagement,
                EngagementState.ANALYSIS,
                reason="returning to analysis to request another approved action",
            )
        raise ControllerError(f"engagement state {engagement.state.value} cannot request actions")

    def _prepare_execution(self, engagement: Engagement) -> Engagement:
        if engagement.state is EngagementState.ACTION_PENDING:
            return engagement
        if engagement.state in {
            EngagementState.READY,
            EngagementState.RECON,
            EngagementState.ANALYSIS,
            EngagementState.WAITING_FOR_APPROVAL,
        }:
            return self._transition(
                engagement,
                EngagementState.ACTION_PENDING,
                reason="policy allowed an approved action",
            )
        raise ControllerError(f"engagement state {engagement.state.value} cannot execute actions")

    # -- engagement ---------------------------------------------------------
    def create_engagement(
        self,
        *,
        name: str,
        mode: EngagementMode | None = None,
        program_id: str | None = None,
        notes: str = "",
        created_by: str | None = None,
    ) -> Engagement:
        moment = self._now()
        engagement = Engagement(
            engagement_id=new_id("eng"),
            name=name,
            mode=mode or self.container.settings.mode,
            state=EngagementState.CREATED,
            program_id=program_id,
            created_at=moment,
            updated_at=moment,
            created_by=created_by or self.container.settings.operator,
            budget_limits=self.container.settings.budget_limits(),
            notes=notes,
        )
        self.container.repos.engagements.save(engagement)
        self._audit(
            engagement_id=engagement.engagement_id,
            actor_type=ActorType.OPERATOR,
            actor_id=engagement.created_by,
            action="engagement_created",
            outcome=engagement.state.value,
            correlation_id=engagement.engagement_id,
            details={"mode": engagement.mode.value, "name": name[:200]},
        )
        return engagement

    def get_engagement(self, engagement_id: str) -> Engagement:
        return self._reload(engagement_id)

    def list_engagements(self, limit: int = 100) -> tuple[Engagement, ...]:
        return tuple(self.container.repos.engagements.list_all(limit=limit))

    def close_engagement(self, engagement_id: str, *, reason: str) -> Engagement:
        engagement = self._reload(engagement_id)
        if engagement.state in {EngagementState.CLOSED, EngagementState.CANCELLED, EngagementState.FAILED}:
            raise ControllerError(f"engagement is already terminal: {engagement.state.value}")
        if not can_transition(engagement.state, EngagementState.CLOSED):
            engagement = self._transition(
                engagement,
                EngagementState.BLOCKED,
                reason="closing engagement through a blocked state",
            )
        return self._transition(
            engagement,
            EngagementState.CLOSED,
            reason=reason,
            actor_type=ActorType.OPERATOR,
            actor_id=self.container.settings.operator,
        )

    def resume_engagement(self, engagement_id: str, *, reason: str) -> Engagement:
        """Recover a BLOCKED engagement after an operator has investigated.

        Recovery is explicit and audited. It never rewinds the action ledger or
        clears prior evidence; it only reopens the workflow at READY.
        """

        engagement = self._reload(engagement_id)
        if engagement.state is not EngagementState.BLOCKED:
            raise ControllerError(
                f"engagement state {engagement.state.value} is not recoverable; only BLOCKED can resume"
            )
        return self._transition(
            engagement,
            EngagementState.READY,
            reason=reason,
            actor_type=ActorType.OPERATOR,
            actor_id=self.container.settings.operator,
        )

    def cancel_engagement(self, engagement_id: str, *, reason: str) -> Engagement:
        engagement = self._reload(engagement_id)
        if engagement.state in {EngagementState.CLOSED, EngagementState.CANCELLED, EngagementState.FAILED}:
            raise ControllerError(f"engagement is already terminal: {engagement.state.value}")
        return self._transition(
            engagement,
            EngagementState.CANCELLED,
            reason=reason,
            actor_type=ActorType.OPERATOR,
            actor_id=self.container.settings.operator,
        )

    # -- scope and targets --------------------------------------------------
    def set_scope(
        self,
        engagement_id: str,
        draft: object,
        *,
        approved_by: str,
        approval_note: str = "",
        scope_id: str | None = None,
        version: int = 1,
    ) -> ScopeDocument:
        from huntress_contracts import ScopeDraft

        if not isinstance(draft, ScopeDraft):
            raise ControllerError("scope draft must be a ScopeDraft contract")
        engagement = self._reload(engagement_id)
        if engagement.state not in {
            EngagementState.CREATED,
            EngagementState.SCOPE_PENDING,
            EngagementState.READY,
        }:
            raise ControllerError(
                "scope can only be set before analysis or while the engagement is ready"
            )
        if draft.engagement_id != engagement.engagement_id:
            raise ControllerError("scope draft belongs to a different engagement")
        if draft.mode is not engagement.mode:
            raise ControllerError("scope mode must match the engagement mode")
        if engagement.state is EngagementState.CREATED:
            engagement = self._transition(
                engagement,
                EngagementState.SCOPE_PENDING,
                reason="scope approval started",
                actor_type=ActorType.OPERATOR,
                actor_id=approved_by,
            )

        scope = self.container.scope_compiler.compile(
            draft,
            profiles=self.container.profiles.all(),
            approved_by=approved_by,
            approved_at=self._now(),
            scope_id=scope_id,
            version=version,
            approval_note=approval_note,
        )
        self.container.repos.scopes.save(scope)
        policy_version = f"huntress-policy/1.0:scope-v{scope.version}:{scope.content_hash[:16]}"
        updated = engagement.model_copy(
            update={
                "scope_id": scope.scope_id,
                "scope_version": scope.version,
                "policy_version": policy_version,
                "program_id": scope.program_id,
                "updated_at": self._now(),
            }
        )
        self.container.repos.engagements.save(updated)
        if updated.state is EngagementState.SCOPE_PENDING:
            updated = self._transition(
                updated,
                EngagementState.READY,
                reason="scope approved and sealed",
                actor_type=ActorType.OPERATOR,
                actor_id=approved_by,
            )
        self._audit(
            engagement_id=engagement_id,
            actor_type=ActorType.OPERATOR,
            actor_id=approved_by,
            action="scope_approved",
            outcome=scope.scope_id,
            correlation_id=scope.scope_id,
            policy_version=policy_version,
            details={
                "scope_id": scope.scope_id,
                "version": scope.version,
                "content_hash": scope.content_hash,
                "asset_count": len(scope.assets),
                "profile_count": len(scope.allowed_profiles),
                "preapproved_count": len(scope.preapproved_profiles),
            },
        )
        return scope

    def get_scope(self, engagement_id: str) -> ScopeDocument:
        engagement = self._reload(engagement_id)
        scope: ScopeDocument | None = None
        if engagement.scope_id:
            scope = self.container.repos.scopes.get(engagement.scope_id)
        if scope is None:
            scope = self.container.repos.scopes.latest(engagement_id)
        if scope is None:
            raise ScopeNotReady(f"engagement {engagement_id} has no approved scope")
        if not verify_scope_seal(scope, self.container.signing_key):
            raise ScopeNotReady(f"scope {scope.scope_id} failed seal verification")
        return scope

    def add_target(
        self,
        engagement_id: str,
        *,
        asset_id: str,
        url: str | None = None,
        host: str | None = None,
        scheme: str = "https",
        port: int | None = None,
        source: str = "operator",
        notes: str = "",
    ) -> TargetRecord:
        engagement = self._reload(engagement_id)
        scope = self.get_scope(engagement_id)
        asset = scope.asset(asset_id)
        if asset is None:
            raise ControllerError(f"asset {asset_id} is not in the approved scope")
        if asset.policy_status is not ScopeStatus.APPROVED:
            raise ControllerError(f"asset {asset_id} is not approved")

        if url is None and host is None and asset.kind.value == "url":
            url = asset.value
        if url is not None:
            parts = urlsplit(url)
            if parts.scheme not in {"http", "https"} or not parts.hostname:
                raise ControllerError("target URL must be an absolute http(s) URL")
            if parts.query or parts.fragment:
                raise ControllerError("target URL must not contain a query or fragment")
            resolved_host = parts.hostname
            resolved_scheme = parts.scheme
            resolved_port = parts.port or (443 if parts.scheme == "https" else 80)
            base_url = url.rstrip("/")
        else:
            if host is None:
                raise ControllerError("a target requires either a URL or a host")
            resolved_host = host
            resolved_scheme = scheme
            resolved_port = port or (443 if scheme == "https" else 80)
            default_port = 443 if scheme == "https" else 80
            suffix = "" if resolved_port == default_port else f":{resolved_port}"
            base_url = f"{resolved_scheme}://{resolved_host}{suffix}"

        existing = [
            target
            for target in self.container.repos.targets.list_by_engagement(engagement_id)
            if target.base_url.rstrip("/") == base_url
        ]
        if existing:
            return existing[0]

        moment = self._now()
        target = TargetRecord(
            target_id=new_id("tgt"),
            engagement_id=engagement.engagement_id,
            asset_id=asset.asset_id,
            asset_kind=asset.kind,
            host=resolved_host,
            scheme=resolved_scheme,
            port=resolved_port,
            base_url=base_url,
            source=source,
            first_seen=moment,
            last_seen=moment,
            notes=notes,
        )
        self.container.repos.targets.save(target)
        self._audit(
            engagement_id=engagement_id,
            actor_type=ActorType.OPERATOR,
            actor_id=self.container.settings.operator,
            action="target_registered",
            outcome=target.target_id,
            correlation_id=target.target_id,
            details={
                "asset_id": target.asset_id,
                "host": target.host,
                "port": target.port,
                "scheme": target.scheme,
            },
        )
        return target

    def sync_targets(self, engagement_id: str) -> tuple[TargetRecord, ...]:
        scope = self.get_scope(engagement_id)
        created: list[TargetRecord] = []
        for asset in scope.assets:
            if asset.kind.value == "url":
                created.append(
                    self.add_target(
                        engagement_id,
                        asset_id=asset.asset_id,
                        source="scope-sync",
                    )
                )
            elif asset.kind.value in {"domain", "ipv4"}:
                port = 443
                scheme = "https"
                if asset.allowed_ports and 443 not in asset.allowed_ports:
                    port = asset.allowed_ports[0]
                    scheme = "https" if port == 443 else "http"
                created.append(
                    self.add_target(
                        engagement_id,
                        asset_id=asset.asset_id,
                        host=asset.value,
                        scheme=scheme,
                        port=port,
                        source="scope-sync",
                    )
                )
        # De-duplicate while preserving order.
        unique: dict[str, TargetRecord] = {target.target_id: target for target in created}
        return tuple(unique.values())

    def list_targets(self, engagement_id: str) -> tuple[TargetRecord, ...]:
        return tuple(self.container.repos.targets.list_by_engagement(engagement_id))

    # -- actions and approvals ---------------------------------------------
    def request_action(
        self,
        *,
        engagement_id: str,
        profile_id: str | None = None,
        target_id: str | None = None,
        action: ActionKind = ActionKind.RUN_APPROVED_PROFILE,
        hypothesis_id: str | None = None,
        evidence_ids: Sequence[str] = (),
        source: DecisionSource = DecisionSource.OPERATOR,
        source_decision_id: str | None = None,
        requested_by: str | None = None,
        reason: str = "",
        approval_ttl_seconds: int | None = None,
    ) -> ActionPlan:
        engagement = self._prepare_for_action(self._reload(engagement_id))
        scope = self.get_scope(engagement_id)
        target = self.container.repos.targets.get(target_id) if target_id else None
        if target_id is not None and target is None:
            raise ControllerError(f"unknown target: {target_id}")
        profile = self.container.profiles.get(profile_id) if profile_id else None
        if profile_id is not None and profile is None:
            raise ProfileUnknown(f"unknown execution profile: {profile_id}")

        request_id = new_id("req")
        request = ActionRequest(
            request_id=request_id,
            engagement_id=engagement.engagement_id,
            action=action,
            target_id=target_id,
            profile_id=profile_id,
            hypothesis_id=hypothesis_id,
            evidence_ids=tuple(evidence_ids),
            idempotency_key=f"act:{request_id}",
            requested_by=(requested_by or self.container.settings.operator)[:200],
            requested_at=self._now(),
            source_decision_id=source_decision_id,
            source=source,
        )
        self.container.repos.action_requests.save(request)
        self._audit(
            engagement_id=engagement_id,
            actor_type=ActorType.AGENT if source is DecisionSource.MODEL else ActorType.OPERATOR,
            actor_id=request.requested_by,
            action="action_requested",
            outcome=action.value,
            correlation_id=request.request_id,
            tool_profile=profile_id,
            details={
                "request_id": request.request_id,
                "target_id": target_id or "",
                "profile_id": profile_id or "",
                "source": source.value,
            },
        )

        decision = self.container.gateway.evaluate(
            request=request,
            engagement=engagement,
            scope=scope,
            target=target,
            profile=profile,
            signing_key=self.container.signing_key,
            now=self._now(),
        )
        if decision.allowed:
            if action is not ActionKind.RUN_APPROVED_PROFILE:
                return ActionPlan(request=request, decision=decision)
            outcome = self._execute_planned(
                request=request,
                engagement=engagement,
                scope=scope,
                target=target,
                profile=profile,
                approval=None,
            )
            return ActionPlan(request=request, decision=decision, outcome=outcome)

        if decision.requires_approval:
            approval_request = self.container.approval_service.create_request(
                request=request,
                scope=scope,
                requested_by=request.requested_by,
                reason=reason or f"profile {profile_id} requires explicit human approval",
                ttl_seconds=approval_ttl_seconds or self.container.settings.approval_ttl_seconds,
                now=self._now(),
            )
            self.container.repos.approvals.save_request(approval_request)
            engagement = self._reload(engagement_id)
            if engagement.state in {
                EngagementState.READY,
                EngagementState.RECON,
                EngagementState.ANALYSIS,
                EngagementState.ACTION_PENDING,
            }:
                engagement = self._transition(
                    engagement,
                    EngagementState.WAITING_FOR_APPROVAL,
                    reason="action requires a human approval",
                    correlation_id=approval_request.approval_id,
                )
            self._audit(
                engagement_id=engagement_id,
                actor_type=ActorType.SYSTEM,
                actor_id="controller",
                action="approval_requested",
                outcome=approval_request.status.value,
                correlation_id=approval_request.approval_id,
                tool_profile=profile_id,
                details={
                    "approval_id": approval_request.approval_id,
                    "request_id": request.request_id,
                    "action_fingerprint": approval_request.action_fingerprint,
                    "expires_at": approval_request.expires_at.isoformat(),
                },
            )
            return ActionPlan(
                request=request,
                decision=decision,
                approval_request=approval_request,
            )

        self._audit(
            engagement_id=engagement_id,
            actor_type=ActorType.SYSTEM,
            actor_id="controller",
            action="action_denied",
            outcome=decision.reason_code.value,
            correlation_id=request.request_id,
            tool_profile=profile_id,
            details={"reasons": "; ".join(decision.reasons)[:1000]},
        )
        return ActionPlan(request=request, decision=decision)

    def _execute_planned(
        self,
        *,
        request: ActionRequest,
        engagement: Engagement,
        scope: ScopeDocument,
        target: TargetRecord | None,
        profile: ToolProfile | None,
        approval: ApprovalRecord | None,
    ) -> ExecutionOutcome:
        if target is None or profile is None:
            raise ControllerError("an executable action requires a target and profile")
        engagement = self._prepare_execution(self._reload(engagement.engagement_id))
        decision = self.container.gateway.evaluate(
            request=request,
            engagement=engagement,
            scope=scope,
            target=target,
            profile=profile,
            signing_key=self.container.signing_key,
            approval=approval,
            now=self._now(),
        )
        if not decision.allowed:
            raise ActionDenied(decision)

        moment = self._now()
        deadline = min(
            moment + timedelta(seconds=profile.timeout_seconds + 30),
            decision.expires_at,
            scope.testing_window.ends_at,
        )
        if deadline <= moment:
            raise ControllerError("execution window is already closed")
        execution_request = ExecutionRequest(
            execution_id=new_id("exe"),
            engagement_id=engagement.engagement_id,
            request_id=request.request_id,
            policy_decision_id=decision.decision_id,
            attempt_id=new_id("att"),
            target_id=target.target_id,
            profile_id=profile.profile_id,
            profile_version=profile.version,
            idempotency_key=request.idempotency_key,
            created_at=moment,
            deadline=deadline,
        )

        engagement = self._transition(
            engagement,
            EngagementState.EXECUTING,
            reason=f"executing reviewed profile {profile.profile_id}",
            actor_type=ActorType.EXECUTOR,
            actor_id="execution-service",
            correlation_id=request.request_id,
        )
        try:
            outcome = self.container.execution.execute(
                request=execution_request,
                decision=decision,
                engagement=engagement,
                scope=scope,
                target=target,
                signing_key=self.container.signing_key,
                approval=approval,
                now=moment,
            )
        except (ExecutionDenied, IdempotentReplay, HuntressError) as exc:
            current = self._reload(engagement.engagement_id)
            if current.state is EngagementState.EXECUTING:
                self._transition(
                    current,
                    EngagementState.BLOCKED,
                    reason=f"execution refused: {type(exc).__name__}",
                    correlation_id=request.request_id,
                )
            self._audit(
                engagement_id=engagement.engagement_id,
                actor_type=ActorType.EXECUTOR,
                actor_id="execution-service",
                action="execution_refused",
                outcome=type(exc).__name__,
                correlation_id=request.request_id,
                tool_profile=profile.profile_id,
                details={"error": str(exc)[:1000]},
            )
            raise

        current = self._reload(engagement.engagement_id)
        if current.state is EngagementState.EXECUTING:
            self._transition(
                current,
                EngagementState.ANALYSIS,
                reason="execution finished; evidence is ready for analysis",
                correlation_id=request.request_id,
            )
        self._audit(
            engagement_id=engagement.engagement_id,
            actor_type=ActorType.EXECUTOR,
            actor_id="execution-service",
            action="execution_finished",
            outcome=outcome.run_result.status.value,
            correlation_id=request.request_id,
            policy_version=decision.policy_version,
            tool_profile=profile.profile_id,
            details={
                "attempt_id": outcome.attempt.attempt_id,
                "findings": len(outcome.findings),
                "requests": outcome.run_result.request_count,
                "artifact_count": len(outcome.run_result.artifact_refs),
                "backend": outcome.backend,
            },
        )
        return outcome

    def execute_request(
        self,
        request_id: str,
        *,
        approval_id: str | None = None,
    ) -> ExecutionOutcome:
        request = self.container.repos.action_requests.get(request_id)
        if request is None:
            raise ControllerError(f"unknown action request: {request_id}")
        engagement = self._reload(request.engagement_id)
        scope = self.get_scope(request.engagement_id)
        target = self.container.repos.targets.get(request.target_id) if request.target_id else None
        profile = self.container.profiles.get(request.profile_id) if request.profile_id else None
        approval = (
            self.container.repos.approvals.get_approval(approval_id)
            if approval_id
            else self._find_approval(request)
        )
        return self._execute_planned(
            request=request,
            engagement=engagement,
            scope=scope,
            target=target,
            profile=profile,
            approval=approval,
        )

    def _find_approval(self, request: ActionRequest) -> ApprovalRecord | None:
        records = [
            record
            for record in self.container.repos.approvals.list_records(request.engagement_id)
            if record.request_id == request.request_id
            and record.status is ApprovalStatus.APPROVED
        ]
        if not records:
            return None
        return max(records, key=lambda record: record.approved_at)

    def pending_approvals(self, engagement_id: str) -> tuple[ApprovalRequest, ...]:
        return tuple(self.container.repos.approvals.list_pending(engagement_id))

    def approve_action(
        self,
        approval_id: str,
        *,
        approved_by: str,
        note: str = "",
        execute: bool = True,
    ) -> ApprovalOutcome:
        request = self.container.repos.approvals.get_request(approval_id)
        if request is None:
            raise ControllerError(f"unknown approval request: {approval_id}")
        if request.status is not ApprovalStatus.PENDING:
            raise ControllerError(f"approval request is {request.status.value}, not pending")
        scope = self.get_scope(request.engagement_id)
        if request.scope_hash != scope.content_hash:
            raise ControllerError("scope changed since the approval was requested")
        record = self.container.approval_service.approve(
            approval_request=request,
            scope=scope,
            approved_by=approved_by,
            signing_key=self.container.signing_key,
            note=note,
            ttl_seconds=self.container.settings.approval_ttl_seconds,
            now=self._now(),
        )
        self.container.repos.approvals.save_record(record)
        approved_request = request.model_copy(update={"status": ApprovalStatus.APPROVED})
        self.container.repos.approvals.save_request(approved_request)
        self._audit(
            engagement_id=request.engagement_id,
            actor_type=ActorType.OPERATOR,
            actor_id=approved_by,
            action="approval_granted",
            outcome=record.status.value,
            correlation_id=record.approval_id,
            details={
                "approval_id": record.approval_id,
                "request_id": record.request_id,
                "action_fingerprint": record.action_fingerprint,
                "scope_hash": record.scope_hash,
            },
        )
        outcome = (
            self.execute_request(record.request_id, approval_id=record.approval_id)
            if execute
            else None
        )
        return ApprovalOutcome(record=record, outcome=outcome)

    def reject_action(
        self,
        approval_id: str,
        *,
        rejected_by: str,
        note: str = "",
    ) -> ApprovalRecord:
        request = self.container.repos.approvals.get_request(approval_id)
        if request is None:
            raise ControllerError(f"unknown approval request: {approval_id}")
        if request.status is not ApprovalStatus.PENDING:
            raise ControllerError(f"approval request is {request.status.value}, not pending")
        scope = self.get_scope(request.engagement_id)
        record = self.container.approval_service.reject(
            approval_request=request,
            scope=scope,
            rejected_by=rejected_by,
            signing_key=self.container.signing_key,
            note=note,
            now=self._now(),
        )
        self.container.repos.approvals.save_record(record)
        self.container.repos.approvals.save_request(
            request.model_copy(update={"status": ApprovalStatus.REJECTED})
        )
        engagement = self._reload(request.engagement_id)
        if engagement.state is EngagementState.WAITING_FOR_APPROVAL:
            self._transition(
                engagement,
                EngagementState.ANALYSIS,
                reason="human rejected the requested action",
                actor_type=ActorType.OPERATOR,
                actor_id=rejected_by,
                correlation_id=record.approval_id,
            )
        self._audit(
            engagement_id=request.engagement_id,
            actor_type=ActorType.OPERATOR,
            actor_id=rejected_by,
            action="approval_rejected",
            outcome=record.status.value,
            correlation_id=record.approval_id,
            details={"approval_id": record.approval_id, "request_id": record.request_id},
        )
        return record

    # -- validation ---------------------------------------------------------
    def validate_finding(
        self,
        *,
        engagement_id: str,
        tool_finding_ids: Sequence[str],
        bug_class_id: str,
        title: str,
        claim: str,
        severity_band: SeverityBand | None = None,
        cvss_vector: str | None = None,
        impact_summary: str | None = None,
        exploitability_summary: str = "",
        uncertainty: str = "",
        side_effect: SideEffectClass | None = None,
        performed_repetitions: int | None = None,
        hypothesis_id: str | None = None,
        finding_id: str | None = None,
    ) -> ValidationOutcome:
        engagement = self._reload(engagement_id)
        scope = self.get_scope(engagement_id)
        if not tool_finding_ids:
            raise ControllerError("at least one tool finding is required")
        findings: list[ToolFinding] = []
        for finding_identifier in tool_finding_ids:
            finding = self.container.repos.findings.get(finding_identifier)
            if finding is None:
                raise ControllerError(f"unknown tool finding: {finding_identifier}")
            findings.append(finding)
        records = tuple(findings)
        target_ids = {finding.target_id for finding in records}
        if len(target_ids) != 1:
            raise ControllerError("all tool findings must belong to one target")
        target = self.container.repos.targets.get(next(iter(target_ids)))
        if target is None:
            raise ControllerError("the finding target is not registered")
        try:
            bug_class = get_bug_class(bug_class_id)
        except KeyError as exc:
            raise ControllerError(str(exc)) from exc

        profile_id = records[0].tool_profile_id
        profile = self.container.profiles.get(profile_id)
        resolved_side_effect = side_effect or (
            profile.side_effect_class if profile is not None else SideEffectClass.READ_ONLY
        )
        severity = (
            SeverityInputs(
                impact_summary=impact_summary or f"{title} was observed on an approved target.",
                cvss_vector=cvss_vector,
                band=severity_band,
                exploitability_summary=exploitability_summary,
                uncertainty=uncertainty,
            )
            if severity_band is not None or cvss_vector is not None or impact_summary
            else None
        )
        reproduction = ReproductionEvidence(
            performed_repetitions=(
                performed_repetitions
                if performed_repetitions is not None
                else self._performed_repetitions(records, bug_class.oracle_archetype.value)
            )
        )

        engagement = self._prepare_validation(engagement)
        request = ValidationRequest(
            engagement=engagement,
            scope=scope,
            target=target,
            bug_class=bug_class,
            findings=records,
            title=title,
            claim=claim,
            method=profile.allowed_methods[0] if profile is not None else "GET",  # type: ignore[arg-type]
            signing_key=self.container.signing_key,
            oracle_facts=self._oracle_facts(records, bug_class.oracle_archetype.value),
            reproduction=reproduction,
            severity=severity,
            side_effect=resolved_side_effect,
            hypothesis_id=hypothesis_id,
            finding_id=finding_id,
            now=self._now(),
        )
        outcome = self.container.validation.validate(request)
        current = self._reload(engagement_id)
        if current.state is EngagementState.VALIDATING:
            if outcome.status is ValidationStatus.PASSED:
                self._transition(
                    current,
                    EngagementState.HUMAN_REVIEW,
                    reason="validated finding is ready for human review",
                    correlation_id=outcome.finding.finding_id,
                )
            elif outcome.status is ValidationStatus.BLOCKED:
                self._transition(
                    current,
                    EngagementState.BLOCKED,
                    reason="validation scope gate blocked the candidate",
                    correlation_id=outcome.finding.finding_id,
                )
            else:
                self._transition(
                    current,
                    EngagementState.ANALYSIS,
                    reason=f"validation finished with {outcome.status.value}",
                    correlation_id=outcome.finding.finding_id,
                )
        self._audit(
            engagement_id=engagement_id,
            actor_type=ActorType.VALIDATOR,
            actor_id="validation-service",
            action="validation_finished",
            outcome=outcome.status.value,
            correlation_id=outcome.finding.finding_id,
            details={
                "finding_id": outcome.finding.finding_id,
                "bug_class_id": bug_class_id,
                "oracle": outcome.oracle.status.value,
                "reproduction": outcome.reproduction.result.status.value,
                "severity": outcome.severity.assessment.band.value,
                "dedup": outcome.dedup.status.value,
            },
        )
        return outcome

    def _prepare_validation(self, engagement: Engagement) -> Engagement:
        if engagement.state is EngagementState.VALIDATING:
            return engagement
        if can_transition(engagement.state, EngagementState.VALIDATING):
            return self._transition(
                engagement,
                EngagementState.VALIDATING,
                reason="candidate submitted to the deterministic validation pipeline",
                actor_type=ActorType.VALIDATOR,
                actor_id="validation-service",
            )
        raise ControllerError(f"engagement state {engagement.state.value} cannot validate findings")

    @staticmethod
    def _performed_repetitions(findings: tuple[ToolFinding, ...], oracle: str) -> int:
        if oracle == "differential_statistical":
            for finding in findings:
                value = finding.details.get("repetitions")
                if isinstance(value, int) and value > 0:
                    return min(value, 10)
            return 1
        if oracle == "state_change_authz":
            return 2
        return 1

    def _artifact_text(self, ref: str) -> str | None:
        if not self.container.store.exists(ref):
            return None
        return self.container.store.get_text(ref)

    def _find_needle(
        self,
        findings: tuple[ToolFinding, ...],
        needles: Sequence[str],
    ) -> tuple[str, str] | None:
        for finding in findings:
            for ref in finding.artifact_refs:
                text = self._artifact_text(ref)
                if text is None:
                    continue
                for needle in needles:
                    if needle and needle in text:
                        return ref, needle
        return None

    def _oracle_facts(
        self,
        findings: tuple[ToolFinding, ...],
        oracle: str,
    ) -> dict[str, str | int | float | bool]:
        if oracle == "content_match":
            return self._content_match_facts(findings)
        if oracle == "differential_statistical":
            return self._differential_facts(findings)
        return {}

    def _content_match_facts(
        self,
        findings: tuple[ToolFinding, ...],
    ) -> dict[str, str | int | float | bool]:
        for finding in findings:
            kind = finding.finding_type
            if kind in {"http.env_exposure", "http.actuator_exposure"}:
                for ref in finding.artifact_refs:
                    text = self._artifact_text(ref)
                    if text is None:
                        continue
                    if kind == "http.env_exposure":
                        match = _SECRET_ASSIGNMENT.search(text)
                        if match:
                            return {
                                "content_ref": ref,
                                "expected_text": match.group(0).strip(),
                                "match_mode": "contains",
                            }
                    else:
                        for needle in ('"propertySources"', '"activeProfiles"', '"systemProperties"'):
                            if needle in text:
                                return {
                                    "content_ref": ref,
                                    "expected_text": needle,
                                    "match_mode": "contains",
                                }
            elif kind == "http.git_exposure":
                found = self._find_needle((finding,), ("ref: refs/",))
                if found:
                    return {
                        "content_ref": found[0],
                        "expected_text": found[1],
                        "match_mode": "contains",
                    }
                for ref in finding.artifact_refs:
                    text = self._artifact_text(ref)
                    if text is not None and _GIT_HEAD.fullmatch(text.strip()):
                        return {
                            "content_ref": ref,
                            "expected_text": text.strip(),
                            "match_mode": "contains",
                        }
            elif kind == "http.directory_listing":
                found = self._find_needle((finding,), ("Index of /",))
                if found:
                    return {
                        "content_ref": found[0],
                        "expected_text": found[1],
                        "match_mode": "contains",
                    }
            elif kind == "http.server_status":
                found = self._find_needle((finding,), ("Apache Server Status", "Server Status"))
                if found:
                    return {
                        "content_ref": found[0],
                        "expected_text": found[1],
                        "match_mode": "contains",
                    }
            elif kind == "http.phpinfo":
                found = self._find_needle((finding,), ("PHP Version",))
                if found:
                    return {
                        "content_ref": found[0],
                        "expected_text": found[1],
                        "match_mode": "contains",
                    }
            elif kind == "http.ds_store":
                found = self._find_needle((finding,), ("Bud1",))
                if found:
                    return {
                        "content_ref": found[0],
                        "expected_text": found[1],
                        "match_mode": "contains",
                    }
            elif kind == "http.backup_exposure":
                for ref in finding.artifact_refs:
                    if not self.container.store.exists(ref):
                        continue
                    data = self.container.store.get(ref)
                    if data.startswith(b"PK\x03\x04"):
                        return {"content_ref": ref, "expected_sha256": sha256_hex(data)}
            elif kind == "http.cors_credentials":
                allow_origin = finding.details.get("allow_origin")
                if isinstance(allow_origin, str) and allow_origin:
                    found = self._find_needle((finding,), (allow_origin,))
                    if found:
                        return {
                            "content_ref": found[0],
                            "expected_text": found[1],
                            "match_mode": "contains",
                        }
            elif kind == "http.open_redirect":
                location = finding.details.get("location")
                if isinstance(location, str) and location:
                    found = self._find_needle((finding,), (location,))
                    if found:
                        return {
                            "content_ref": found[0],
                            "expected_text": found[1],
                            "match_mode": "contains",
                        }
            elif kind == "http.reflected_html_marker":
                marker = finding.details.get("marker")
                if isinstance(marker, str) and marker:
                    found = self._find_needle((finding,), (marker,))
                    if found:
                        return {
                            "content_ref": found[0],
                            "expected_text": found[1],
                            "match_mode": "contains",
                        }
        return {}

    def _differential_facts(
        self,
        findings: tuple[ToolFinding, ...],
    ) -> dict[str, str | int | float | bool]:
        for finding in findings:
            if finding.finding_type != "http.error_based_sqli":
                continue
            baseline_ref = finding.details.get("baseline_artifact_ref")
            probe_text = finding.details.get("probe_artifact_refs")
            if not isinstance(baseline_ref, str) or not isinstance(probe_text, str):
                continue
            probe_refs = tuple(ref for ref in probe_text.split(",") if ref)
            if not probe_refs:
                continue
            signature: str | None = None
            for probe_ref in probe_refs:
                text = self._artifact_text(probe_ref)
                if text is None:
                    continue
                matched = _sql_error_signature(text)
                if matched:
                    signature = matched
                    break
            if signature is None:
                declared = finding.details.get("signature")
                if isinstance(declared, str) and declared:
                    for probe_ref in probe_refs:
                        text = self._artifact_text(probe_ref)
                        if text is None:
                            continue
                        try:
                            match = re.search(declared, text)
                        except re.error:
                            match = None
                        if match:
                            signature = match.group(0)
                            break
                        if declared in text:
                            signature = declared
                            break
            if signature is None:
                continue
            declared_repetitions = finding.details.get("repetitions")
            repetitions = (
                declared_repetitions
                if isinstance(declared_repetitions, int) and declared_repetitions > 0
                else len(probe_refs)
            )
            return {
                "baseline_ref": baseline_ref,
                "probe_refs": ",".join(probe_refs),
                "min_trials": 3,
                "repetitions": repetitions,
                "signal": "error_signature",
                "error_signature": signature,
            }
        return {}

    # -- human review -------------------------------------------------------
    def review_finding(
        self,
        finding_id: str,
        *,
        reviewer: str,
        decision: HumanReviewStatus,
        notes: str = "",
    ) -> ReviewOutcome:
        finding = self.container.repos.validations.get(finding_id)
        if finding is None:
            raise ReviewDenied(f"unknown finding: {finding_id}")
        engagement = self._reload(finding.engagement_id)
        if engagement.state not in {
            EngagementState.HUMAN_REVIEW,
            EngagementState.VALIDATING,
            EngagementState.ANALYSIS,
            EngagementState.READY,
        }:
            raise ControllerError(
                f"engagement state {engagement.state.value} cannot accept a review decision"
            )
        if engagement.state is not EngagementState.HUMAN_REVIEW:
            engagement = self._transition(
                engagement,
                EngagementState.HUMAN_REVIEW,
                reason="human review requested for a validated finding",
                actor_type=ActorType.OPERATOR,
                actor_id=reviewer,
                correlation_id=finding_id,
            )
        outcome = self.container.reviews.review(
            finding_id=finding_id,
            reviewer=reviewer,
            decision=decision,
            notes=notes,
            now=self._now(),
        )
        current = self._reload(engagement.engagement_id)
        if current.state is EngagementState.HUMAN_REVIEW:
            target = (
                EngagementState.REPORT_DRAFT
                if decision is HumanReviewStatus.APPROVED
                else EngagementState.ANALYSIS
            )
            self._transition(
                current,
                target,
                reason=f"human review decision: {decision.value}",
                actor_type=ActorType.OPERATOR,
                actor_id=reviewer,
                correlation_id=finding_id,
            )
        self._audit(
            engagement_id=engagement.engagement_id,
            actor_type=ActorType.OPERATOR,
            actor_id=reviewer,
            action="human_review_recorded",
            outcome=decision.value,
            correlation_id=finding_id,
            details={"review_id": outcome.review.review_id, "notes_length": len(notes)},
        )
        return outcome

    # -- reporting ----------------------------------------------------------
    def draft_report(
        self,
        *,
        engagement_id: str,
        finding_ids: Sequence[str] = (),
        title: str | None = None,
        summary: str | None = None,
        impact: str | None = None,
        reproduction_steps: Sequence[str] = (),
        remediation: str = "",
        references: Sequence[str] = (),
        platform: str | None = None,
        destination: str = "none",
        require_approved: bool = True,
    ) -> VulnerabilityReport:
        engagement = self._reload(engagement_id)
        scope = self.get_scope(engagement_id)
        if finding_ids:
            findings: list[ValidatedFinding] = []
            for identifier in finding_ids:
                finding = self.container.repos.validations.get(identifier)
                if finding is None:
                    raise ReportNotReady(f"unknown validated finding: {identifier}")
                findings.append(finding)
        else:
            findings = [
                finding
                for finding in self.container.repos.validations.list_by_engagement(engagement_id)
                if finding.status is ValidationStatus.PASSED
                and finding.dedup.status is DuplicateStatus.UNIQUE
                and all(gate.status is GateStatus.PASS for gate in finding.gates)
                and (
                    not require_approved
                    or finding.human_review_status is HumanReviewStatus.APPROVED
                )
            ]
        if not findings:
            raise ReportNotReady("no passed, unique, approved findings are available for a report")

        engagement = self._prepare_report_draft(engagement)
        steps = tuple(reproduction_steps) or self._default_steps(tuple(findings))
        report = self.container.report_builder.build(
            findings=tuple(findings),
            reproduction_steps=steps,
            title=title,
            summary=summary,
            impact=impact,
            remediation=remediation,
            references=references,
            platform=platform or scope.reporting.platform,
            destination=destination,
            now=self._now(),
        )
        self.container.reports.save_draft(report)
        self._audit(
            engagement_id=engagement_id,
            actor_type=ActorType.OPERATOR,
            actor_id=self.container.settings.operator,
            action="report_drafted",
            outcome=report.status.value,
            correlation_id=report.report_id,
            details={
                "report_id": report.report_id,
                "finding_count": len(findings),
                "content_hash": report.content_hash,
            },
        )
        return report

    @staticmethod
    def _default_steps(findings: tuple[ValidatedFinding, ...]) -> tuple[str, ...]:
        steps: list[str] = []
        for finding in findings:
            steps.append(
                f"Review the preserved evidence for finding {finding.finding_id} "
                f"({', '.join(finding.evidence_refs[:3])})."
            )
            steps.append(
                f"Re-run the reviewed profile that produced {finding.title!r} against the "
                "same approved target and compare the same deterministic marker."
            )
        return tuple(steps)

    def _prepare_report_draft(self, engagement: Engagement) -> Engagement:
        if engagement.state is EngagementState.REPORT_DRAFT:
            return engagement
        if can_transition(engagement.state, EngagementState.REPORT_DRAFT):
            return self._transition(
                engagement,
                EngagementState.REPORT_DRAFT,
                reason="approved findings are being assembled into a report draft",
                actor_type=ActorType.OPERATOR,
                actor_id=self.container.settings.operator,
            )
        raise ControllerError(f"engagement state {engagement.state.value} cannot draft a report")

    def request_report_approval(self, report_id: str) -> VulnerabilityReport:
        report = self.container.reports.request_approval(report_id=report_id, now=self._now())
        engagement = self._reload(report.engagement_id)
        if engagement.state is EngagementState.REPORT_DRAFT:
            self._transition(
                engagement,
                EngagementState.SUBMISSION_PENDING,
                reason="report submission approval requested",
                actor_type=ActorType.OPERATOR,
                actor_id=self.container.settings.operator,
                correlation_id=report_id,
            )
        self._audit(
            engagement_id=report.engagement_id,
            actor_type=ActorType.OPERATOR,
            actor_id=self.container.settings.operator,
            action="report_approval_requested",
            outcome=report.status.value,
            correlation_id=report_id,
            details={"content_hash": report.content_hash},
        )
        return report

    def approve_report(
        self,
        report_id: str,
        *,
        approved_by: str,
        destination: str,
        note: str = "",
    ) -> VulnerabilityReport:
        report = self.container.reports.get(report_id)
        if report is None:
            raise ControllerError(f"unknown report: {report_id}")
        engagement = self._reload(report.engagement_id)
        if engagement.state is EngagementState.REPORT_DRAFT:
            engagement = self._transition(
                engagement,
                EngagementState.SUBMISSION_PENDING,
                reason="report submission approval requested",
                actor_type=ActorType.OPERATOR,
                actor_id=approved_by,
                correlation_id=report_id,
            )
        if engagement.state is not EngagementState.SUBMISSION_PENDING:
            raise ControllerError(
                f"engagement state {engagement.state.value} is not awaiting report approval"
            )
        approved = self.container.reports.approve_submission(
            report_id=report_id,
            approved_by=approved_by,
            destination=destination,
            note=note,
            now=self._now(),
        )
        self._audit(
            engagement_id=approved.engagement_id,
            actor_type=ActorType.OPERATOR,
            actor_id=approved_by,
            action="report_submission_approved",
            outcome=approved.status.value,
            correlation_id=report_id,
            details={
                "content_hash": approved.content_hash,
                "destination": destination[:500],
                "approval_id": approved.approval.approval_id if approved.approval else "",
            },
        )
        return approved

    def submit_report(self, report_id: str) -> VulnerabilityReport:
        report = self.container.reports.get(report_id)
        if report is None:
            raise ControllerError(f"unknown report: {report_id}")
        engagement = self._reload(report.engagement_id)
        if engagement.state is not EngagementState.SUBMISSION_PENDING:
            raise ControllerError(
                f"engagement state {engagement.state.value} is not awaiting submission"
            )
        submitted = self.container.reports.mark_submitted(report_id=report_id, now=self._now())
        self._transition(
            engagement,
            EngagementState.CLOSED,
            reason="human-approved report submitted",
            actor_type=ActorType.OPERATOR,
            actor_id=self.container.settings.operator,
            correlation_id=report_id,
        )
        self._audit(
            engagement_id=submitted.engagement_id,
            actor_type=ActorType.OPERATOR,
            actor_id=self.container.settings.operator,
            action="report_submitted",
            outcome=submitted.status.value,
            correlation_id=report_id,
            details={"content_hash": submitted.content_hash},
        )
        return submitted

    def withdraw_report(self, report_id: str, *, reason: str) -> VulnerabilityReport:
        report = self.container.reports.get(report_id)
        if report is None:
            raise ControllerError(f"unknown report: {report_id}")
        withdrawn = self.container.reports.withdraw(
            report_id=report_id,
            reason=reason,
            now=self._now(),
        )
        engagement = self._reload(withdrawn.engagement_id)
        if engagement.state is EngagementState.SUBMISSION_PENDING:
            self._transition(
                engagement,
                EngagementState.REPORT_DRAFT,
                reason="report submission withdrawn",
                actor_type=ActorType.OPERATOR,
                actor_id=self.container.settings.operator,
                correlation_id=report_id,
            )
        self._audit(
            engagement_id=withdrawn.engagement_id,
            actor_type=ActorType.OPERATOR,
            actor_id=self.container.settings.operator,
            action="report_withdrawn",
            outcome=withdrawn.status.value,
            correlation_id=report_id,
            details={"reason": reason[:1000]},
        )
        return withdrawn

    # -- reasoning ----------------------------------------------------------
    def reason(
        self,
        *,
        engagement_id: str,
        objective: str,
        use_model: bool = False,
        task: ContextTask = ContextTask.ACTION_SELECTION,
    ) -> ReasoningResult:
        if task is not ContextTask.ACTION_SELECTION:
            raise ControllerError("this release exposes action-selection reasoning only")
        engagement = self._reload(engagement_id)
        scope = self.get_scope(engagement_id)
        targets = self.list_targets(engagement_id)
        tool_findings = self.container.repos.findings.list_by_engagement(engagement_id)
        evidence_items = tuple(
            EvidenceDigestItem(
                finding_id=finding.finding_id,
                target_id=finding.target_id,
                finding_type=finding.finding_type,
                confidence=finding.confidence,
                artifact_refs=finding.artifact_refs,
                excerpt=finding.excerpt,
            )
            for finding in tool_findings[-self.container.settings.reasoning_max_evidence_items :]
        )
        allowed_evidence = tuple(item.finding_id for item in evidence_items)
        hypotheses = self.container.repos.hypotheses.list_by_engagement(engagement_id)
        decisions = self.container.repos.decisions.list_by_engagement(engagement_id)
        attempts = self.container.repos.attempts.list_by_engagement(engagement_id)
        attempted_profiles = tuple(dict.fromkeys(attempt.profile_id for attempt in attempts))
        reviewed_evidence = tuple(
            dict.fromkeys(
                evidence_id
                for decision in decisions
                if decision.action is ActionKind.REVIEW_EVIDENCE
                for evidence_id in decision.evidence_ids
            )
        )
        working_memory = "\n".join(
            f"- {decision.created_at.isoformat()} {decision.action.value}: "
            f"{decision.rationale_summary[:300]}"
            for decision in decisions[-8:]
        ) or "No prior decisions recorded."
        budget = self.container.budget.snapshot(
            engagement_id,
            engagement.budget_limits,
            self._now(),
        )
        try:
            knowledge = self.container.knowledge.retrieve(
                RetrievalQuery(
                    tenant_scope=engagement_id,
                    text=objective,
                    limit=5,
                ),
                tenant_scope=engagement_id,
            )
        except HuntressError:
            knowledge = ()
        compiled = self.container.context_compiler.compile(
            ContextRequest(
                engagement=engagement,
                scope=scope,
                task=task,
                targets=targets,
                objective=objective,
                budget_snapshot=budget,
                output_contract=output_contract(task),
                evidence=evidence_items,
                knowledge=knowledge,
                working_memory=working_memory,
                allowed_profile_ids=scope.allowed_profiles,
                allowed_hypothesis_ids=tuple(hypothesis.hypothesis_id for hypothesis in hypotheses),
                allowed_evidence_ids=allowed_evidence,
                now=self._now(),
            )
        )
        if use_model:
            service = self.container.reasoning_service()
            outcome: DecisionOutcome = service.select_action(compiled=compiled, now=self._now())
            return ReasoningResult(
                packet=compiled.packet,
                rendered=compiled.rendered,
                decision=outcome.decision,
                used_model=True,
                errors=outcome.errors,
            )

        planner = RuleBasedPlanner()
        decision = planner.select_action(
            compiled.packet,
            reviewed_evidence_ids=reviewed_evidence,
            attempted_profile_ids=attempted_profiles,
            now=self._now(),
        )
        self.container.repos.decisions.save(decision)
        self._audit(
            engagement_id=engagement_id,
            actor_type=ActorType.AGENT,
            actor_id="rule-based-planner",
            action="decision_recorded",
            outcome=decision.action.value,
            correlation_id=decision.decision_id,
            details={
                "target_id": decision.target_id or "",
                "profile_id": decision.profile_id or "",
                "evidence_count": len(decision.evidence_ids),
                "source": decision.source.value,
            },
        )
        return ReasoningResult(
            packet=compiled.packet,
            rendered=compiled.rendered,
            decision=decision,
            used_model=False,
        )

    # -- status and audit ---------------------------------------------------
    def status(self, engagement_id: str) -> EngagementStatus:
        engagement = self._reload(engagement_id)
        try:
            scope = self.get_scope(engagement_id)
        except ScopeNotReady:
            scope = None
        budget = self.container.budget.snapshot(
            engagement_id,
            engagement.budget_limits,
            self._now(),
        )
        return EngagementStatus(
            engagement=engagement,
            scope=scope,
            budget=budget,
            targets=self.list_targets(engagement_id),
            attempts=tuple(self.container.repos.attempts.list_by_engagement(engagement_id)),
            tool_findings=tuple(self.container.repos.findings.list_by_engagement(engagement_id)),
            validated_findings=tuple(
                self.container.repos.validations.list_by_engagement(engagement_id)
            ),
            pending_approvals=self.pending_approvals(engagement_id),
            reports=tuple(self.container.repos.reports.list_by_engagement(engagement_id)),
            audit=self.container.repos.audit.verify_chain(engagement_id),
        )

    def audit_verify(self, engagement_id: str | None = None) -> AuditChainVerification:
        return self.container.repos.audit.verify_chain(engagement_id)

    def audit_events(self, engagement_id: str | None = None, limit: int = 200) -> tuple[AuditEvent, ...]:
        return tuple(self.container.repos.audit.list_events(engagement_id, limit=limit))

    def checkpoints(self, engagement_id: str) -> tuple[Checkpoint, ...]:
        # The repository exposes only the latest checkpoint by design; callers
        # that need history should query the transition stream.
        latest = self.container.repos.checkpoints.latest(engagement_id)
        return (latest,) if latest is not None else ()


def _sql_error_signature(text: str) -> str | None:
    """Extract the actual database-error text matched by the reviewed parser.

    The parser stores the regex pattern, not the matched substring. The
    differential oracle needs a literal substring so it can prove the signal
    is present in every probe and absent from the baseline.
    """

    from huntress_scanning.parsers import sql_error_match

    return sql_error_match(text)


__all__ = [
    "ActionDenied",
    "ActionPlan",
    "ApprovalOutcome",
    "Controller",
    "ControllerError",
    "EngagementNotFound",
    "EngagementStatus",
    "ReasoningResult",
    "ScopeNotReady",
]
