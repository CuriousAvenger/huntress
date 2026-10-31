"""Policy-rechecked, idempotent execution service.

The service is the only component that turns an allowing ``PolicyDecision``
into a side effect. It performs, in order:

    decision binding validation → idempotency reservation → budget reservation
    → fixed profile resolution → full policy recheck → backend invocation
    → artifact capture → finding/attempt persistence → ledger/budget settlement

Every failure after invocation is recorded as a non-success ``ToolRunResult``;
no output is discarded just because a command failed.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime

from huntress_contracts import (
    ActionKind,
    ActionLedgerEntry,
    ActionRequest,
    Actor,
    ActorType,
    ApprovalRecord,
    ArtifactProvenance,
    AuditEvent,
    BudgetReservation,
    Engagement,
    ExecutionRequest,
    HttpMethod,
    LedgerStatus,
    PolicyDecision,
    ProfileExecutor,
    ReasonCode,
    RedactionStatus,
    ScopeDocument,
    TargetRecord,
    TestAttempt,
    ToolFinding,
    ToolProfile,
    ToolRunResult,
    ToolRunStatus,
    ensure_utc,
    new_id,
    utc_now,
)
from huntress_contracts import (
    ExecutionBackend as BackendMode,
)
from huntress_evidence import ArtifactStore, artifact_provenance
from huntress_governance import BudgetExceeded, BudgetManager, PolicyGateway, ScopeGuard

from .errors import (
    BackendContractError,
    BackendUnavailable,
    ExecutionDenied,
    IdempotentReplay,
)
from .models import (
    AttemptStore,
    AuditSink,
    BackendContext,
    BackendOutput,
    ExecutionBackendPort,
    ExecutionLedger,
    ExecutionOutcome,
    FindingStore,
)
from .profiles import DEFAULT_PROFILE_REGISTRY, ProfileRegistry

logger = logging.getLogger(__name__)


class ExecutionService:
    """Execute reviewed profiles under policy, budget, and evidence control."""

    def __init__(
        self,
        *,
        store: ArtifactStore,
        attempts: AttemptStore,
        findings: FindingStore,
        ledger: ExecutionLedger,
        budget: BudgetManager,
        gateway: PolicyGateway | None = None,
        scope_guard: ScopeGuard | None = None,
        profiles: ProfileRegistry | None = None,
        builtin_backend: ExecutionBackendPort | None = None,
        exegol_backend: ExecutionBackendPort | None = None,
        fake_backend: ExecutionBackendPort | None = None,
        backend_mode: BackendMode = BackendMode.AUTO,
        audit: AuditSink | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._store = store
        self._attempts = attempts
        self._findings = findings
        self._ledger = ledger
        self._budget = budget
        self._scope_guard = scope_guard or ScopeGuard()
        self._gateway = gateway or PolicyGateway(
            budget=budget,
            ledger=ledger,
            scope_guard=self._scope_guard,
        )
        self._profiles = profiles or DEFAULT_PROFILE_REGISTRY
        self._builtin_backend = builtin_backend
        self._exegol_backend = exegol_backend
        self._fake_backend = fake_backend
        self._backend_mode = backend_mode
        self._audit = audit
        self._clock = clock

    def execute(
        self,
        *,
        request: ExecutionRequest,
        decision: PolicyDecision,
        engagement: Engagement,
        scope: ScopeDocument,
        target: TargetRecord,
        signing_key: bytes,
        approval: ApprovalRecord | None = None,
        now: datetime | None = None,
    ) -> ExecutionOutcome:
        moment = self._moment(now)
        profile = self._profiles.require(request.profile_id)
        self._validate_binding(
            request=request,
            decision=decision,
            engagement=engagement,
            scope=scope,
            target=target,
            profile=profile,
            approval=approval,
            moment=moment,
        )

        existing = self._ledger.get(request.idempotency_key)
        if existing is not None:
            self._audit_denial(
                request=request,
                decision=decision,
                outcome=ReasonCode.DENIED_IDEMPOTENT_REPLAY,
                reason="idempotency key already reserved",
                moment=moment,
            )
            raise IdempotentReplay(existing)

        entry = ActionLedgerEntry(
            idempotency_key=request.idempotency_key,
            request_id=request.request_id,
            engagement_id=request.engagement_id,
            action_fingerprint=self._action_request(request).action_fingerprint(),
            status=LedgerStatus.RESERVED,
            reserved_at=moment,
            updated_at=moment,
        )
        if not self._ledger.reserve(entry):
            existing = self._ledger.get(request.idempotency_key)
            if existing is None:  # pragma: no cover - reservation lost after a conflict
                raise BackendContractError("idempotency reservation conflicted but no entry exists")
            raise IdempotentReplay(existing)

        reservation: BudgetReservation | None = None
        try:
            reservation = self._reserve_budget(
                request=request,
                engagement=engagement,
                target=target,
                profile=profile,
                moment=moment,
            )
            recheck = self._gateway.recheck(
                request=self._action_request(request),
                engagement=engagement,
                scope=scope,
                target=target,
                profile=profile,
                signing_key=signing_key,
                approval=approval,
                now=moment,
            )
            if not recheck.allowed:
                raise ExecutionDenied(recheck.reason_code, recheck.reasons)
            if (
                decision.requires_approval
                and decision.approval_id is not None
                and (approval is None or approval.approval_id != decision.approval_id)
            ):
                raise ExecutionDenied(
                    ReasonCode.DENIED_APPROVAL_INVALID,
                    ("approval does not match the decision's validated approval",),
                )

            backend = self._select_backend(profile)
            if self._clock() >= request.deadline:
                raise ExecutionDenied(
                    ReasonCode.DENIED_INVALID_REQUEST,
                    ("execution deadline passed before backend invocation",),
                )

            executing = entry.model_copy(
                update={"status": LedgerStatus.EXECUTING, "updated_at": self._clock()}
            )
            self._ledger.update(executing)
            started_at = self._clock()
            context = BackendContext(
                request=request,
                profile=profile,
                engagement=engagement,
                target=target,
                scope=scope,
                authorize_url=self._authorizer(scope=scope, signing_key=signing_key),
                policy_version=decision.policy_version,
                scope_hash=scope.content_hash,
                now=moment,
            )
            try:
                output = backend.execute(context)
            except Exception as exc:
                logger.exception("execution backend %s raised", getattr(backend, "name", "unknown"))
                output = BackendOutput(
                    status=ToolRunStatus.FAILED,
                    error_code="backend_exception",
                    error_message=f"{type(exc).__name__}: {exc}"[:2000],
                    backend=getattr(backend, "name", "unknown"),
                )
            finished_at = self._clock()
            return self._finalize(
                request=request,
                decision=decision,
                engagement=engagement,
                target=target,
                profile=profile,
                backend=backend,
                output=output,
                reservation=reservation,
                entry=executing,
                started_at=started_at,
                finished_at=finished_at,
            )
        except ExecutionDenied as exc:
            self._release(reservation)
            self._fail_ledger(entry, exc.reason_code.value, self._clock())
            self._audit_denial(
                request=request,
                decision=decision,
                outcome=exc.reason_code,
                reason="; ".join(exc.reasons),
                moment=self._clock(),
            )
            raise
        except BackendUnavailable as exc:
            self._release(reservation)
            self._fail_ledger(entry, "backend_unavailable", self._clock())
            self._audit_denial(
                request=request,
                decision=decision,
                outcome=ReasonCode.DENIED_INVALID_REQUEST,
                reason=str(exc),
                moment=self._clock(),
            )
            raise
        except BudgetExceeded as exc:
            self._fail_ledger(entry, "budget_exceeded", self._clock())
            self._audit_denial(
                request=request,
                decision=decision,
                outcome=exc.reason_code,
                reason=str(exc),
                moment=self._clock(),
            )
            raise

    def _validate_binding(
        self,
        *,
        request: ExecutionRequest,
        decision: PolicyDecision,
        engagement: Engagement,
        scope: ScopeDocument,
        target: TargetRecord,
        profile: ToolProfile,
        approval: ApprovalRecord | None,
        moment: datetime,
    ) -> None:
        if not decision.allowed:
            raise ExecutionDenied(decision.reason_code, decision.reasons or ("decision denied",))
        if decision.request_id != request.request_id:
            raise ExecutionDenied(ReasonCode.DENIED_INVALID_REQUEST, ("decision request id mismatch",))
        if decision.engagement_id != request.engagement_id:
            raise ExecutionDenied(ReasonCode.DENIED_INVALID_REQUEST, ("decision engagement mismatch",))
        if decision.action_fingerprint != self._action_request(request).action_fingerprint():
            raise ExecutionDenied(
                ReasonCode.DENIED_INVALID_REQUEST,
                ("decision action fingerprint does not match the request",),
            )
        if decision.scope_hash != scope.content_hash:
            raise ExecutionDenied(
                ReasonCode.DENIED_SCOPE_INTEGRITY,
                ("decision was made against a different scope version",),
            )
        if moment < decision.decided_at:
            raise ExecutionDenied(ReasonCode.DENIED_INVALID_REQUEST, ("decision is not yet valid",))
        if moment >= decision.expires_at:
            raise ExecutionDenied(ReasonCode.DENIED_INVALID_REQUEST, ("policy decision expired",))
        if moment >= request.deadline:
            raise ExecutionDenied(ReasonCode.DENIED_INVALID_REQUEST, ("execution deadline passed",))
        if engagement.engagement_id != request.engagement_id:
            raise ExecutionDenied(ReasonCode.DENIED_UNKNOWN_ENGAGEMENT, ("engagement mismatch",))
        if scope.engagement_id != request.engagement_id:
            raise ExecutionDenied(ReasonCode.DENIED_SCOPE_MISSING, ("scope engagement mismatch",))
        if target.engagement_id != request.engagement_id:
            raise ExecutionDenied(ReasonCode.DENIED_TARGET_NOT_FOUND, ("target engagement mismatch",))
        if target.target_id != request.target_id:
            raise ExecutionDenied(ReasonCode.DENIED_TARGET_NOT_FOUND, ("target id mismatch",))
        if profile.profile_id != request.profile_id:
            raise ExecutionDenied(ReasonCode.DENIED_PROFILE_UNKNOWN, ("profile id mismatch",))
        if profile.version != request.profile_version:
            raise ExecutionDenied(ReasonCode.DENIED_PROFILE_UNKNOWN, ("profile version mismatch",))
        if decision.requires_approval:
            if approval is None:
                raise ExecutionDenied(
                    ReasonCode.DENIED_APPROVAL_REQUIRED,
                    ("profile requires a human approval record",),
                )
            if decision.approval_id is not None and approval.approval_id != decision.approval_id:
                raise ExecutionDenied(
                    ReasonCode.DENIED_APPROVAL_INVALID,
                    ("approval does not match the decision's validated approval",),
                )

    def _reserve_budget(
        self,
        *,
        request: ExecutionRequest,
        engagement: Engagement,
        target: TargetRecord,
        profile: ToolProfile,
        moment: datetime,
    ) -> BudgetReservation:
        reservation = BudgetReservation(
            reservation_id=new_id("br"),
            engagement_id=request.engagement_id,
            request_id=request.request_id,
            idempotency_key=request.idempotency_key,
            host=target.host,
            requests=profile.max_requests_per_run,
            actions=1,
            created_at=moment,
        )
        return self._budget.reserve(
            engagement_id=engagement.engagement_id,
            limits=engagement.budget_limits,
            reservation=reservation,
        )

    def _select_backend(self, profile: ToolProfile) -> ExecutionBackendPort:
        if self._backend_mode is BackendMode.FAKE:
            if self._fake_backend is None:
                raise BackendUnavailable("fake backend requested but not configured")
            return self._fake_backend
        if self._backend_mode is BackendMode.EXEGOL:
            if self._exegol_backend is None:
                raise BackendUnavailable("Exegol backend requested but not configured")
            return self._exegol_backend
        if profile.executor is ProfileExecutor.BUILTIN:
            if self._builtin_backend is None:
                raise BackendUnavailable("builtin backend is not configured")
            return self._builtin_backend
        if self._exegol_backend is None:
            raise BackendUnavailable("Exegol profile requires a configured Exegol backend")
        return self._exegol_backend

    def _authorizer(self, *, scope: ScopeDocument, signing_key: bytes) -> Callable[[str, HttpMethod], bool]:
        def authorize(url: str, method: HttpMethod) -> bool:
            check = self._scope_guard.check_redirect(
                scope=scope,
                url=url,
                method=method,
                now=self._clock(),
                signing_key=signing_key,
            )
            return check.allowed

        return authorize

    def _finalize(
        self,
        *,
        request: ExecutionRequest,
        decision: PolicyDecision,
        engagement: Engagement,
        target: TargetRecord,
        profile: ToolProfile,
        backend: ExecutionBackendPort,
        output: BackendOutput,
        reservation: BudgetReservation,
        entry: ActionLedgerEntry,
        started_at: datetime,
        finished_at: datetime,
    ) -> ExecutionOutcome:
        status = output.status
        timed_out = output.timed_out or status is ToolRunStatus.TIMEOUT
        error_code = output.error_code
        error_message = output.error_message

        if timed_out and status is not ToolRunStatus.TIMEOUT:
            status = ToolRunStatus.TIMEOUT
        if status is ToolRunStatus.SUCCEEDED and finished_at > request.deadline:
            status = ToolRunStatus.TIMEOUT
            timed_out = True
            error_code = "deadline_exceeded"
            error_message = "backend completed after the execution deadline"

        invalid_findings = self._invalid_findings(output.findings, request=request, profile=profile)
        if invalid_findings:
            status = ToolRunStatus.FAILED
            error_code = "invalid_backend_findings"
            error_message = (
                f"backend returned {len(invalid_findings)} finding(s) outside the execution "
                "binding; findings were not persisted"
            )
            findings: tuple[ToolFinding, ...] = ()
        else:
            findings = output.findings

        invalid_refs = [ref for ref in output.artifact_refs if not self._valid_ref(ref)]
        if invalid_refs:
            status = ToolRunStatus.FAILED
            error_code = "invalid_artifact_ref"
            error_message = "backend returned a malformed artifact reference"
            backend_refs: tuple[str, ...] = ()
        else:
            backend_refs = output.artifact_refs

        limit = profile.max_output_bytes
        stdout, stdout_cut = self._cap(output.stdout, limit)
        stderr, stderr_cut = self._cap(output.stderr, limit)
        combined = stdout
        if stderr:
            combined = stdout + (b"\n--- stderr ---\n" if stdout else b"") + stderr
        output_truncated = output.output_truncated or stdout_cut or stderr_cut
        if len(combined) > limit:
            combined = combined[:limit]
            output_truncated = True

        provenance = artifact_provenance(
            source_tool=f"{profile.profile_id}@{profile.version}",
            tool_version=profile.version,
            engagement_id=request.engagement_id,
            target_id=request.target_id,
            asset_id=target.asset_id,
            profile_id=profile.profile_id,
            action_request_id=request.request_id,
            policy_version=decision.policy_version,
            scope_hash=decision.scope_hash,
            exit_status=output.exit_code,
            redaction_status=RedactionStatus.RAW,
            now=started_at,
        )
        stdout_ref = self._put(stdout, provenance=provenance, note="stdout")
        stderr_ref = self._put(stderr, provenance=provenance, note="stderr")
        combined_ref = self._put(combined, provenance=provenance, note="combined output")
        artifact_refs = tuple(
            dict.fromkeys(
                ref
                for ref in (stdout_ref, stderr_ref, combined_ref, *backend_refs)
                if ref is not None
            )
        )

        duration_ms = max(0, int((finished_at - started_at).total_seconds() * 1000))
        run_result = ToolRunResult(
            attempt_id=request.attempt_id,
            execution_id=request.execution_id,
            engagement_id=request.engagement_id,
            target_id=request.target_id,
            profile_id=profile.profile_id,
            profile_version=profile.version,
            status=status,
            exit_code=output.exit_code,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=duration_ms,
            stdout_ref=stdout_ref,
            stderr_ref=stderr_ref,
            combined_ref=combined_ref,
            artifact_refs=artifact_refs,
            output_truncated=output_truncated,
            timed_out=timed_out,
            error_code=error_code,
            error_message=error_message[:2000],
            request_count=max(0, output.request_count),
            side_effect_class=profile.side_effect_class,
            backend=output.backend or getattr(backend, "name", "unknown"),
        )
        attempt = TestAttempt(
            attempt_id=request.attempt_id,
            engagement_id=request.engagement_id,
            request_id=request.request_id,
            policy_decision_id=decision.decision_id,
            target_id=request.target_id,
            profile_id=profile.profile_id,
            profile_version=profile.version,
            idempotency_key=request.idempotency_key,
            status=status,
            side_effect_class=profile.side_effect_class,
            started_at=started_at,
            finished_at=finished_at,
            artifact_refs=artifact_refs,
            exit_code=output.exit_code,
            result_summary=(
                f"{profile.profile_id} {status.value}; exit={output.exit_code}; "
                f"requests={run_result.request_count}; findings={len(findings)}"
            )[:2000],
            error_code=error_code,
            result_ref=combined_ref or stdout_ref,
        )

        try:
            self._attempts.save(attempt)
            if findings:
                self._findings.save_many(findings)
        except Exception as exc:
            logger.exception("failed to persist execution outcome")
            self._fail_ledger(entry, "persistence_error", finished_at)
            self._budget.commit(reservation.reservation_id, actions=1)
            raise BackendContractError(f"failed to persist execution outcome: {exc}") from exc

        final_status = LedgerStatus.COMPLETED if status is ToolRunStatus.SUCCEEDED else LedgerStatus.FAILED
        final_entry = entry.model_copy(
            update={
                "status": final_status,
                "updated_at": finished_at,
                "artifact_refs": artifact_refs,
                "result_ref": combined_ref or stdout_ref,
                "error_code": error_code,
            }
        )
        self._ledger.update(final_entry)
        self._budget.commit(reservation.reservation_id, actions=1)

        self._audit_outcome(
            request=request,
            decision=decision,
            attempt=attempt,
            run_result=run_result,
            finding_count=len(findings),
            moment=finished_at,
        )
        return ExecutionOutcome(
            request=request,
            decision=decision,
            run_result=run_result,
            attempt=attempt,
            findings=findings,
            ledger_entry=final_entry,
            budget_reservation=reservation,
            backend=run_result.backend,
        )

    @staticmethod
    def _invalid_findings(
        findings: tuple[ToolFinding, ...],
        *,
        request: ExecutionRequest,
        profile: ToolProfile,
    ) -> tuple[ToolFinding, ...]:
        return tuple(
            finding
            for finding in findings
            if finding.engagement_id != request.engagement_id
            or finding.target_id != request.target_id
            or finding.tool_profile_id != profile.profile_id
        )

    @staticmethod
    def _valid_ref(ref: str) -> bool:
        return len(ref) == 64 and all(char in "0123456789abcdef" for char in ref)

    @staticmethod
    def _cap(data: bytes, limit: int) -> tuple[bytes, bool]:
        if len(data) <= limit:
            return data, False
        return data[:limit], True

    def _put(self, data: bytes, *, provenance: ArtifactProvenance, note: str) -> str | None:
        if not data:
            return None
        ref = self._store.put(
            data,
            media_type="text/plain; charset=utf-8",
            provenance=provenance.model_copy(update={"note": note}),
            redaction_status=RedactionStatus.RAW,
        )
        return ref.sha256

    def _release(self, reservation: BudgetReservation | None) -> None:
        if reservation is not None:
            self._budget.release(reservation.reservation_id)

    def _fail_ledger(self, entry: ActionLedgerEntry, error_code: str, moment: datetime) -> None:
        self._ledger.update(
            entry.model_copy(
                update={
                    "status": LedgerStatus.FAILED,
                    "updated_at": ensure_utc(moment),
                    "error_code": error_code[:80],
                }
            )
        )

    def _audit_outcome(
        self,
        *,
        request: ExecutionRequest,
        decision: PolicyDecision,
        attempt: TestAttempt,
        run_result: ToolRunResult,
        finding_count: int,
        moment: datetime,
    ) -> None:
        details: dict[str, str | int | float | bool] = {
            "attempt_id": attempt.attempt_id,
            "execution_id": request.execution_id,
            "target_id": request.target_id,
            "profile_version": run_result.profile_version,
            "status": run_result.status.value,
            "request_count": run_result.request_count,
            "finding_count": finding_count,
            "duration_ms": run_result.duration_ms,
            "artifact_count": len(run_result.artifact_refs),
            "backend": run_result.backend,
        }
        if run_result.exit_code is not None:
            details["exit_code"] = run_result.exit_code
        if run_result.error_code:
            details["error_code"] = run_result.error_code
        self._emit(
            request=request,
            decision=decision,
            action="tool_execution",
            outcome=run_result.status.value,
            moment=moment,
            details=details,
        )

    def _audit_denial(
        self,
        *,
        request: ExecutionRequest,
        decision: PolicyDecision,
        outcome: ReasonCode,
        reason: str,
        moment: datetime,
    ) -> None:
        self._emit(
            request=request,
            decision=decision,
            action="tool_execution_denied",
            outcome=outcome.value,
            moment=moment,
            details={"reason": reason[:1000], "target_id": request.target_id},
        )

    def _emit(
        self,
        *,
        request: ExecutionRequest,
        decision: PolicyDecision,
        action: str,
        outcome: str,
        moment: datetime,
        details: dict[str, str | int | float | bool],
    ) -> None:
        if self._audit is None:
            return
        event = AuditEvent(
            event_id=new_id("aud"),
            occurred_at=ensure_utc(moment),
            engagement_id=request.engagement_id,
            actor=Actor(type=ActorType.EXECUTOR, id="execution-service"),
            action=action,
            outcome=outcome[:80],
            correlation_id=request.request_id,
            policy_version=decision.policy_version,
            tool_profile=request.profile_id,
            details=details,
        )
        self._audit.append(event)

    def _action_request(self, request: ExecutionRequest) -> ActionRequest:
        """Build the policy-facing request without widening the model surface."""

        if request.target_id is None or request.profile_id is None:  # pragma: no cover
            raise ExecutionDenied(
                ReasonCode.DENIED_INVALID_REQUEST,
                ("execution request is missing a target or profile",),
            )
        return ActionRequest(
            request_id=request.request_id,
            engagement_id=request.engagement_id,
            action=ActionKind.RUN_APPROVED_PROFILE,
            target_id=request.target_id,
            profile_id=request.profile_id,
            idempotency_key=request.idempotency_key,
            requested_by="execution-service",
            requested_at=request.created_at,
        )

    def _moment(self, now: datetime | None) -> datetime:
        return ensure_utc(now) if now is not None else ensure_utc(self._clock())
