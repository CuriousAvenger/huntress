"""Deterministic validation pipeline.

Order is fixed and matches the architecture document:

    scope recheck → evidence completeness → reproduction policy → technical
    oracle → severity → deduplication → durable record

Every gate is evaluated even when an earlier gate fails so the persisted
record explains the full candidate state. Status precedence is: a scope
failure blocks, any other failure fails, any inconclusive/skipped gate leaves
the candidate inconclusive, and only all-pass becomes ``PASSED``.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime

from huntress_contracts import (
    Actor,
    ActorType,
    AuditEvent,
    GateName,
    GateResult,
    GateStatus,
    HumanReviewStatus,
    ToolFinding,
    ValidatedFinding,
    ValidationStatus,
    ensure_utc,
    new_id,
    utc_now,
)
from huntress_evidence import ArtifactStore

from .errors import ValidationConflict, VerificationError
from .gates import DeduplicationGate, EvidenceGate, ScopeGate
from .models import AuditSink, ValidationOutcome, ValidationRequest, ValidationStore
from .oracles import DEFAULT_ORACLE_REGISTRY, OracleRegistry, OracleRequest
from .reproduction import (
    DEFAULT_REPRODUCTION_POLICY,
    ReproductionPolicy,
)
from .severity import SeverityAssessor

logger = logging.getLogger(__name__)


class ValidationService:
    """Turn a candidate claim into a durable, gate-checked finding record."""

    def __init__(
        self,
        *,
        store: ArtifactStore,
        validations: ValidationStore,
        oracle_registry: OracleRegistry | None = None,
        reproduction_policy: ReproductionPolicy | None = None,
        severity_assessor: SeverityAssessor | None = None,
        scope_gate: ScopeGate | None = None,
        evidence_gate: EvidenceGate | None = None,
        dedup_gate: DeduplicationGate | None = None,
        audit: AuditSink | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._store = store
        self._validations = validations
        self._oracles = oracle_registry or DEFAULT_ORACLE_REGISTRY
        self._reproduction = reproduction_policy or DEFAULT_REPRODUCTION_POLICY
        self._severity = severity_assessor or SeverityAssessor()
        self._scope_gate = scope_gate or ScopeGate()
        self._evidence_gate = evidence_gate or EvidenceGate()
        self._dedup_gate = dedup_gate or DeduplicationGate()
        self._audit = audit
        self._clock = clock

    def validate(self, request: ValidationRequest) -> ValidationOutcome:
        moment = self._moment(request.now)
        finding_id = request.finding_id or new_id("vf")
        if request.finding_id is not None and self._validations.get(finding_id) is not None:
            raise ValidationConflict(f"finding {finding_id} already exists")

        scope_result = self._scope_gate.evaluate(
            engagement=request.engagement,
            scope=request.scope,
            target=request.target,
            method=request.method,
            signing_key=request.signing_key,
            now=moment,
        )
        evidence_result, verified_refs = self._evidence_gate.evaluate(
            engagement=request.engagement,
            scope=request.scope,
            target=request.target,
            bug_class=request.bug_class,
            findings=request.findings,
            store=self._store,
            now=moment,
        )
        reproduction_outcome = self._reproduction.evaluate(
            bug_class=request.bug_class,
            side_effect=request.side_effect,
            evidence=request.reproduction,
        )
        oracle_result = self._oracles.evaluate(
            OracleRequest(
                archetype=request.bug_class.oracle_archetype,
                target=request.target,
                evidence_refs=verified_refs or self._all_refs(request.findings),
                facts=request.oracle_facts,
                store=self._store,
                now=moment,
            )
        )
        severity_outcome = self._severity.assess(
            bug_class=request.bug_class,
            inputs=request.severity,
        )
        prior = self._validations.list_by_engagement(request.engagement.engagement_id)
        dedup_gate, dedup_result = self._dedup_gate.evaluate(
            engagement_id=request.engagement.engagement_id,
            target_id=request.target.target_id,
            bug_class=request.bug_class,
            findings=request.findings,
            prior_findings=tuple(prior),
            now=moment,
        )

        gates = (
            scope_result,
            evidence_result,
            GateResult(
                gate=GateName.REPRODUCIBILITY,
                status=reproduction_outcome.gate_status,
                reason=reproduction_outcome.reason,
                evidence_refs=verified_refs,
                checked_at=moment,
                checker_version=reproduction_outcome.result.policy_id[:40],
            ),
            GateResult(
                gate=GateName.TECHNICAL_ORACLE,
                status=oracle_result.status,
                reason=oracle_result.reason,
                evidence_refs=oracle_result.evidence_refs,
                checked_at=moment,
                checker_version=oracle_result.oracle_version[:40],
            ),
            GateResult(
                gate=GateName.SEVERITY,
                status=severity_outcome.gate_status,
                reason=severity_outcome.reason,
                evidence_refs=verified_refs,
                checked_at=moment,
                checker_version="severity/1.0",
            ),
            dedup_gate,
        )
        status = self._status(gates)
        evidence_refs = self._evidence_refs(request.findings, verified_refs)

        finding = ValidatedFinding(
            finding_id=finding_id,
            engagement_id=request.engagement.engagement_id,
            hypothesis_id=request.hypothesis_id,
            tool_finding_ids=tuple(finding.finding_id for finding in request.findings),
            target_id=request.target.target_id,
            bug_class_id=request.bug_class.bug_class_id,
            oracle_archetype=request.bug_class.oracle_archetype,
            title=request.title,
            claim=request.claim,
            evidence_refs=evidence_refs,
            gates=gates,
            reproduction=reproduction_outcome.result,
            severity=severity_outcome.assessment,
            dedup=dedup_result,
            status=status,
            validated_at=moment,
            validator_version="validation/1.0",
            human_review_status=(
                HumanReviewStatus.PENDING
                if status is ValidationStatus.PASSED
                else HumanReviewStatus.NOT_REQUIRED
            ),
        )
        try:
            self._validations.save(finding)
        except Exception as exc:
            logger.exception("failed to persist validated finding %s", finding_id)
            raise VerificationError(f"failed to persist validated finding: {exc}") from exc

        self._audit_validation(
            request=request,
            finding=finding,
            oracle_id=oracle_result.oracle_id,
            oracle_status=oracle_result.status,
            moment=moment,
        )
        return ValidationOutcome(
            status=status,
            finding=finding,
            gates=gates,
            oracle=oracle_result,
            reproduction=reproduction_outcome,
            severity=severity_outcome,
            dedup=dedup_result,
        )

    @staticmethod
    def _status(gates: tuple[GateResult, ...]) -> ValidationStatus:
        if any(
            gate.gate is GateName.SCOPE_RECHECK and gate.status is GateStatus.FAIL for gate in gates
        ):
            return ValidationStatus.BLOCKED
        if any(gate.status is GateStatus.FAIL for gate in gates):
            return ValidationStatus.FAILED
        if any(gate.status is not GateStatus.PASS for gate in gates):
            return ValidationStatus.INCONCLUSIVE
        return ValidationStatus.PASSED

    @staticmethod
    def _all_refs(findings: tuple[ToolFinding, ...]) -> tuple[str, ...]:
        return tuple(sorted({ref for finding in findings for ref in finding.artifact_refs}))

    @staticmethod
    def _evidence_refs(
        findings: tuple[ToolFinding, ...], verified_refs: tuple[str, ...]
    ) -> tuple[str, ...]:
        refs = {ref for finding in findings for ref in finding.artifact_refs}
        refs.update(verified_refs)
        return tuple(sorted(refs))

    def _audit_validation(
        self,
        *,
        request: ValidationRequest,
        finding: ValidatedFinding,
        oracle_id: str,
        oracle_status: GateStatus,
        moment: datetime,
    ) -> None:
        if self._audit is None:
            return
        gates = ",".join(f"{gate.gate.value}:{gate.status.value}" for gate in finding.gates)
        event = AuditEvent(
            event_id=new_id("aud"),
            occurred_at=moment,
            engagement_id=request.engagement.engagement_id,
            actor=Actor(type=ActorType.VALIDATOR, id="validation-service"),
            action="finding_validation",
            outcome=finding.status.value,
            correlation_id=finding.finding_id,
            policy_version=request.engagement.policy_version,
            details={
                "target_id": request.target.target_id,
                "bug_class_id": request.bug_class.bug_class_id,
                "oracle": oracle_id[:80],
                "oracle_status": oracle_status.value,
                "severity_band": finding.severity.band.value,
                "dedup_status": finding.dedup.status.value,
                "gates": gates[:1000],
                "tool_finding_count": len(request.findings),
                "evidence_count": len(finding.evidence_refs),
            },
        )
        self._audit.append(event)

    def _moment(self, now: datetime | None) -> datetime:
        return ensure_utc(now) if now is not None else ensure_utc(self._clock())
