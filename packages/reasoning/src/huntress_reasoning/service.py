"""Budgeted reasoning checkpoints with deterministic validation and telemetry.

The service never persists an invalid model proposal as a decision or
hypothesis. It reserves model/token budget before every invocation, commits
actual usage afterwards, records one bounded ``ModelCallRecord`` per attempt,
and emits an audit event for every call and rejection.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from huntress_contracts import (
    Actor,
    ActorType,
    AuditEvent,
    BudgetReservation,
    ContextPacket,
    ContextTask,
    DecisionSource,
    DecisionValidation,
    InvestigationDecision,
    ModelAttribution,
    ModelCallRecord,
    ModelCallStatus,
    VulnerabilityHypothesis,
    ensure_utc,
    get_bug_class,
    new_id,
    utc_now,
)
from huntress_governance import BudgetExceeded, BudgetManager

from .context import CompiledContext
from .errors import PromptVersionMismatch, RuntimeInvocationError, TaskMismatch
from .prompts import prompt_for
from .runtime import StructuredRuntime
from .schemas import (
    DecisionDraft,
    Draft,
    FailureReflectionDraft,
    HypothesisDraft,
    ImpactNarrativeDraft,
    draft_model_for,
)
from .validators import DecisionValidator, HypothesisValidation, HypothesisValidator


class ModelCallSink(Protocol):
    def save(self, record: ModelCallRecord) -> ModelCallRecord: ...


class DecisionSink(Protocol):
    def save(self, decision: InvestigationDecision) -> InvestigationDecision: ...


class HypothesisSink(Protocol):
    def save(self, hypothesis: VulnerabilityHypothesis) -> VulnerabilityHypothesis: ...


class AuditSink(Protocol):
    def append(self, event: AuditEvent) -> AuditEvent: ...


@dataclass(frozen=True, slots=True)
class DecisionOutcome:
    call: ModelCallRecord
    decision: InvestigationDecision | None = None
    validation: DecisionValidation | None = None
    errors: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class HypothesisOutcome:
    call: ModelCallRecord
    hypothesis: VulnerabilityHypothesis | None = None
    validation: HypothesisValidation | None = None
    errors: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ReflectionOutcome:
    call: ModelCallRecord
    reflection: FailureReflectionDraft | None = None
    errors: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ImpactOutcome:
    call: ModelCallRecord
    narrative: ImpactNarrativeDraft | None = None
    errors: tuple[str, ...] = ()


@dataclass(slots=True)
class _Invocation:
    call_id: str
    started_at: datetime
    finished_at: datetime
    input_tokens: int
    output_tokens: int
    cost_usd: float
    status: ModelCallStatus
    output_schema: str
    stop_reason: str = ""
    draft: Draft | None = None
    error_code: str | None = None
    error_message: str = ""


class ReasoningService:
    """Run one bounded reasoning checkpoint at a time."""

    def __init__(
        self,
        *,
        runtime: StructuredRuntime,
        budget: BudgetManager,
        calls: ModelCallSink,
        decisions: DecisionSink,
        hypotheses: HypothesisSink,
        audit: AuditSink | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._runtime = runtime
        self._budget = budget
        self._calls = calls
        self._decisions = decisions
        self._hypotheses = hypotheses
        self._audit = audit
        self._clock = clock
        self._decision_validator = DecisionValidator()
        self._hypothesis_validator = HypothesisValidator()

    # -- public checkpoints -------------------------------------------------

    def select_action(self, *, compiled: CompiledContext, now: datetime | None = None) -> DecisionOutcome:
        invocation = self._invoke(
            compiled=compiled,
            task=ContextTask.ACTION_SELECTION,
            now=now,
        )
        if invocation.draft is None or not isinstance(invocation.draft, DecisionDraft):
            return DecisionOutcome(
                call=self._finalize(invocation, compiled.packet),
                errors=(invocation.error_message or "no decision draft",),
            )

        packet = compiled.packet
        draft = invocation.draft
        decision = InvestigationDecision(
            decision_id=new_id("dec"),
            engagement_id=packet.engagement_id,
            action=draft.action,
            target_id=draft.target_id,
            profile_id=draft.profile_id,
            hypothesis_id=draft.hypothesis_id,
            evidence_ids=draft.evidence_ids,
            rationale_summary=draft.rationale_summary,
            confidence=draft.confidence,
            source=DecisionSource.MODEL,
            created_at=invocation.finished_at,
            model_attribution=self._attribution(invocation.call_id, packet),
        )
        validation = self._decision_validator.validate(decision, packet, now=invocation.finished_at)
        if not validation.valid:
            invocation.status = ModelCallStatus.INVALID_OUTPUT
            invocation.error_code = "invalid_decision_references"
            invocation.error_message = "; ".join(validation.errors)
            return DecisionOutcome(
                call=self._finalize(invocation, packet),
                validation=validation,
                errors=validation.errors,
            )

        self._decisions.save(decision)
        return DecisionOutcome(
            call=self._finalize(invocation, packet),
            decision=decision,
            validation=validation,
        )

    def synthesize_hypothesis(
        self, *, compiled: CompiledContext, now: datetime | None = None
    ) -> HypothesisOutcome:
        invocation = self._invoke(
            compiled=compiled,
            task=ContextTask.HYPOTHESIS_SYNTHESIS,
            now=now,
        )
        packet = compiled.packet
        if invocation.draft is None or not isinstance(invocation.draft, HypothesisDraft):
            return HypothesisOutcome(
                call=self._finalize(invocation, packet),
                errors=(invocation.error_message or "no hypothesis draft",),
            )

        draft = invocation.draft
        try:
            bug_class = get_bug_class(draft.bug_class_id)
        except KeyError:
            return self._reject_hypothesis(
                invocation,
                packet,
                (f"unknown bug class {draft.bug_class_id}",),
            )

        hypothesis = VulnerabilityHypothesis(
            hypothesis_id=new_id("hyp"),
            engagement_id=packet.engagement_id,
            target_id=draft.target_id,
            bug_class_id=draft.bug_class_id,
            oracle_archetype=bug_class.oracle_archetype,
            claim=draft.claim,
            falsification_test=draft.falsification_test,
            rationale_summary=draft.rationale_summary,
            evidence_ids=draft.evidence_ids,
            confidence=draft.confidence,
            suggested_profile_ids=draft.suggested_profile_ids,
            created_at=invocation.finished_at,
            model_attribution=self._attribution(invocation.call_id, packet),
        )
        validation = self._hypothesis_validator.validate(hypothesis, packet, now=invocation.finished_at)
        if not validation.valid:
            return self._reject_hypothesis(invocation, packet, validation.errors, validation)

        self._hypotheses.save(hypothesis)
        return HypothesisOutcome(
            call=self._finalize(invocation, packet),
            hypothesis=hypothesis,
            validation=validation,
        )

    def reflect_on_failure(
        self, *, compiled: CompiledContext, now: datetime | None = None
    ) -> ReflectionOutcome:
        invocation = self._invoke(
            compiled=compiled,
            task=ContextTask.FAILURE_REFLECTION,
            now=now,
        )
        if invocation.draft is None or not isinstance(invocation.draft, FailureReflectionDraft):
            return ReflectionOutcome(
                call=self._finalize(invocation, compiled.packet),
                errors=(invocation.error_message or "no reflection draft",),
            )
        return ReflectionOutcome(
            call=self._finalize(invocation, compiled.packet),
            reflection=invocation.draft,
        )

    def draft_impact(self, *, compiled: CompiledContext, now: datetime | None = None) -> ImpactOutcome:
        invocation = self._invoke(
            compiled=compiled,
            task=ContextTask.IMPACT_NARRATIVE,
            now=now,
        )
        packet = compiled.packet
        if invocation.draft is None or not isinstance(invocation.draft, ImpactNarrativeDraft):
            return ImpactOutcome(
                call=self._finalize(invocation, packet),
                errors=(invocation.error_message or "no impact narrative draft",),
            )

        draft = invocation.draft
        unknown = sorted(set(draft.evidence_ids) - set(packet.allowed_evidence_ids))
        if unknown:
            invocation.status = ModelCallStatus.INVALID_OUTPUT
            invocation.error_code = "invalid_impact_references"
            invocation.error_message = (
                "impact narrative references evidence outside the packet: " + ", ".join(unknown[:5])
            )
            return ImpactOutcome(
                call=self._finalize(invocation, packet),
                errors=(invocation.error_message,),
            )
        return ImpactOutcome(
            call=self._finalize(invocation, packet),
            narrative=draft,
        )

    # -- invocation and accounting -----------------------------------------

    def _invoke(
        self,
        *,
        compiled: CompiledContext,
        task: ContextTask,
        now: datetime | None,
    ) -> _Invocation:
        packet = compiled.packet
        if packet.task is not task:
            raise TaskMismatch(f"packet task is {packet.task.value}, expected {task.value}")
        prompt = prompt_for(task)
        if packet.prompt_version != prompt.version:
            raise PromptVersionMismatch(
                f"packet prompt version {packet.prompt_version!r} does not match "
                f"current prompt {prompt.version!r}"
            )
        output_model = draft_model_for(task)
        if output_model is None:  # pragma: no cover - closed task enum
            raise TaskMismatch(f"no output schema for task {task.value}")

        moment = ensure_utc(now) if now is not None else ensure_utc(self._clock())
        call_id = new_id("mc")
        limits = packet.budget_snapshot.limits
        reserved_tokens = packet.approx_tokens + self._runtime.max_output_tokens
        reserved_cost = self._cost(packet.approx_tokens, self._runtime.max_output_tokens)
        reservation = BudgetReservation(
            reservation_id=new_id("br"),
            engagement_id=packet.engagement_id,
            request_id=new_id("req"),
            idempotency_key=f"model:{call_id}",
            actions=0,
            model_calls=1,
            tokens=reserved_tokens,
            cost_usd=reserved_cost,
            created_at=moment,
        )
        try:
            self._budget.reserve(
                engagement_id=packet.engagement_id,
                limits=limits,
                reservation=reservation,
            )
        except BudgetExceeded as exc:
            self._emit(
                packet=packet,
                call_id=call_id,
                status=ModelCallStatus.BUDGET_EXCEEDED,
                moment=moment,
                details={"error": str(exc)[:1000]},
            )
            raise

        try:
            output = self._runtime.invoke(
                system_prompt=prompt.system,
                prompt=compiled.rendered,
                output_model=output_model,
            )
        except RuntimeInvocationError as exc:
            finished = self._settle(
                reservation.reservation_id,
                exc.input_tokens,
                exc.output_tokens,
            )
            return _Invocation(
                call_id=call_id,
                started_at=moment,
                finished_at=finished,
                input_tokens=exc.input_tokens,
                output_tokens=exc.output_tokens,
                cost_usd=self._cost(exc.input_tokens, exc.output_tokens),
                status=exc.status,
                output_schema=output_model.__name__,
                stop_reason=exc.stop_reason,
                error_code=exc.error_code,
                error_message=str(exc),
            )
        except Exception as exc:  # defensive: a runtime bug is still telemetry
            finished = self._settle(reservation.reservation_id, 0, 0)
            return _Invocation(
                call_id=call_id,
                started_at=moment,
                finished_at=finished,
                input_tokens=0,
                output_tokens=0,
                cost_usd=0.0,
                status=ModelCallStatus.PROVIDER_ERROR,
                output_schema=output_model.__name__,
                error_code=type(exc).__name__[:80],
                error_message=f"{type(exc).__name__}: {exc}",
            )

        finished = self._settle(reservation.reservation_id, output.input_tokens, output.output_tokens)
        if not isinstance(output.output, Draft):
            return _Invocation(
                call_id=call_id,
                started_at=moment,
                finished_at=finished,
                input_tokens=output.input_tokens,
                output_tokens=output.output_tokens,
                cost_usd=self._cost(output.input_tokens, output.output_tokens),
                status=ModelCallStatus.INVALID_OUTPUT,
                output_schema=output_model.__name__,
                stop_reason=output.stop_reason,
                error_code="structured_output_wrong_type",
                error_message=(
                    f"runtime returned {type(output.output).__name__}, expected {output_model.__name__}"
                ),
            )
        return _Invocation(
            call_id=call_id,
            started_at=moment,
            finished_at=finished,
            input_tokens=output.input_tokens,
            output_tokens=output.output_tokens,
            cost_usd=self._cost(output.input_tokens, output.output_tokens),
            status=ModelCallStatus.SUCCEEDED,
            output_schema=output_model.__name__,
            stop_reason=output.stop_reason,
            draft=output.output,
        )

    def _settle(self, reservation_id: str, input_tokens: int, output_tokens: int) -> datetime:
        tokens = max(0, input_tokens) + max(0, output_tokens)
        self._budget.commit(
            reservation_id,
            actions=0,
            tokens=tokens,
            cost_usd=self._cost(input_tokens, output_tokens),
        )
        return ensure_utc(self._clock())

    def _finalize(self, invocation: _Invocation, packet: ContextPacket) -> ModelCallRecord:
        status = invocation.status
        error_code = invocation.error_code if status is not ModelCallStatus.SUCCEEDED else None
        error_message = invocation.error_message[:2000] if status is not ModelCallStatus.SUCCEEDED else ""
        record = ModelCallRecord(
            call_id=invocation.call_id,
            engagement_id=packet.engagement_id,
            checkpoint=packet.task,
            provider=self._runtime.provider,
            model_id=self._runtime.model_id,
            prompt_version=packet.prompt_version,
            context_hash=packet.context_hash,
            started_at=invocation.started_at,
            finished_at=invocation.finished_at,
            status=status,
            stop_reason=invocation.stop_reason[:80],
            input_tokens=invocation.input_tokens,
            output_tokens=invocation.output_tokens,
            cost_usd=round(invocation.cost_usd, 8),
            output_schema=invocation.output_schema,
            error_code=error_code[:80] if error_code else None,
            error_message=error_message,
        )
        self._calls.save(record)
        self._emit(
            packet=packet,
            call_id=invocation.call_id,
            status=status,
            moment=invocation.finished_at,
            details={
                "input_tokens": invocation.input_tokens,
                "output_tokens": invocation.output_tokens,
                "stop_reason": invocation.stop_reason[:80],
                "output_schema": invocation.output_schema,
            },
        )
        return record

    def _reject_hypothesis(
        self,
        invocation: _Invocation,
        packet: ContextPacket,
        errors: tuple[str, ...],
        validation: HypothesisValidation | None = None,
    ) -> HypothesisOutcome:
        invocation.status = ModelCallStatus.INVALID_OUTPUT
        invocation.error_code = "invalid_hypothesis_references"
        invocation.error_message = "; ".join(errors)
        return HypothesisOutcome(
            call=self._finalize(invocation, packet),
            validation=validation,
            errors=errors,
        )

    def _attribution(self, call_id: str, packet: ContextPacket) -> ModelAttribution:
        return ModelAttribution(
            call_id=call_id,
            provider=self._runtime.provider,
            model_id=self._runtime.model_id,
            prompt_version=packet.prompt_version,
            context_hash=packet.context_hash,
        )

    def _cost(self, input_tokens: int, output_tokens: int) -> float:
        return max(
            0.0,
            (max(0, input_tokens) / 1_000_000.0) * self._runtime.input_cost_per_million
            + (max(0, output_tokens) / 1_000_000.0) * self._runtime.output_cost_per_million,
        )

    def _emit(
        self,
        *,
        packet: ContextPacket,
        call_id: str,
        status: ModelCallStatus,
        moment: datetime,
        details: dict[str, str | int | float | bool],
    ) -> None:
        if self._audit is None:
            return
        self._audit.append(
            AuditEvent(
                event_id=new_id("aud"),
                occurred_at=moment,
                engagement_id=packet.engagement_id,
                actor=Actor(type=ActorType.AGENT, id="reasoning-service"),
                action="model_call",
                outcome=status.value,
                correlation_id=call_id,
                policy_version=packet.policy_version,
                model_id=self._runtime.model_id,
                details={"task": packet.task.value, "provider": self._runtime.provider, **details},
            )
        )
