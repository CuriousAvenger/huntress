"""Deterministic validation of model proposals against the compiled packet."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from huntress_contracts import (
    ContextPacket,
    ContextTask,
    DecisionValidation,
    InvestigationDecision,
    ModelAttribution,
    VulnerabilityHypothesis,
    ensure_utc,
    get_bug_class,
    utc_now,
)

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class HypothesisValidation:
    """Deterministic verdict on a proposed hypothesis before persistence."""

    hypothesis_id: str
    valid: bool
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    checked_at: datetime = _EPOCH

    def __post_init__(self) -> None:
        if self.valid and self.errors:
            raise ValueError("a valid hypothesis cannot carry errors")
        if not self.valid and not self.errors:
            raise ValueError("an invalid hypothesis must carry at least one error")


class DecisionValidator:
    """Verify every referenced ID and authority boundary before policy."""

    def validate(
        self,
        decision: InvestigationDecision,
        packet: ContextPacket,
        *,
        now: datetime | None = None,
    ) -> DecisionValidation:
        moment = ensure_utc(now) if now is not None else ensure_utc(utc_now())
        errors: list[str] = []
        warnings: list[str] = []

        if packet.task is not ContextTask.ACTION_SELECTION:
            errors.append("decisions may only be validated against an action-selection packet")
        if decision.engagement_id != packet.engagement_id:
            errors.append("decision engagement does not match the context packet")
        if decision.target_id is not None and decision.target_id not in packet.allowed_target_ids:
            errors.append(f"target {decision.target_id} is not in the allowed target set")
        if decision.profile_id is not None and decision.profile_id not in packet.allowed_profile_ids:
            errors.append(f"profile {decision.profile_id} is not in the allowed profile set")
        if decision.hypothesis_id is not None and decision.hypothesis_id not in packet.allowed_hypothesis_ids:
            errors.append(f"hypothesis {decision.hypothesis_id} is not in the allowed hypothesis set")
        for evidence_id in decision.evidence_ids:
            if evidence_id not in packet.allowed_evidence_ids:
                errors.append(f"evidence {evidence_id} is not in the allowed evidence set")
        if decision.expires_at is not None and decision.expires_at <= moment:
            errors.append("decision has already expired")
        if decision.created_at > moment + timedelta(minutes=5):
            warnings.append("decision creation time is ahead of the validator clock")
        if decision.confidence == 0.0:
            warnings.append("decision carries zero confidence")
        if decision.source.value == "model" and decision.model_attribution is None:
            warnings.append("model decision has no attribution record")
        errors.extend(self._attribution_errors(decision.model_attribution, packet))

        return DecisionValidation(
            decision_id=decision.decision_id,
            valid=not errors,
            errors=tuple(errors),
            warnings=tuple(warnings),
            checked_at=moment,
        )

    @staticmethod
    def _attribution_errors(attribution: ModelAttribution | None, packet: ContextPacket) -> list[str]:
        if attribution is None:
            return []
        errors: list[str] = []
        if attribution.context_hash != packet.context_hash:
            errors.append("model attribution context hash does not match the packet")
        if attribution.prompt_version != packet.prompt_version:
            errors.append("model attribution prompt version does not match the packet")
        return errors


class HypothesisValidator:
    """Verify a hypothesis's bug class, oracle, and references."""

    def validate(
        self,
        hypothesis: VulnerabilityHypothesis,
        packet: ContextPacket,
        *,
        now: datetime | None = None,
    ) -> HypothesisValidation:
        moment = ensure_utc(now) if now is not None else ensure_utc(utc_now())
        errors: list[str] = []
        warnings: list[str] = []

        if packet.task is not ContextTask.HYPOTHESIS_SYNTHESIS:
            errors.append("hypotheses may only be validated against a hypothesis-synthesis packet")
        if hypothesis.engagement_id != packet.engagement_id:
            errors.append("hypothesis engagement does not match the context packet")
        if hypothesis.target_id not in packet.allowed_target_ids:
            errors.append(f"target {hypothesis.target_id} is not in the allowed target set")
        for evidence_id in hypothesis.evidence_ids:
            if evidence_id not in packet.allowed_evidence_ids:
                errors.append(f"evidence {evidence_id} is not in the allowed evidence set")
        for profile_id in hypothesis.suggested_profile_ids:
            if profile_id not in packet.allowed_profile_ids:
                errors.append(f"profile {profile_id} is not in the allowed profile set")

        try:
            bug_class = get_bug_class(hypothesis.bug_class_id)
        except KeyError:
            errors.append(f"unknown bug class {hypothesis.bug_class_id}")
        else:
            if hypothesis.oracle_archetype is not bug_class.oracle_archetype:
                errors.append(
                    f"oracle {hypothesis.oracle_archetype.value} does not match "
                    f"bug class oracle {bug_class.oracle_archetype.value}"
                )
        if hypothesis.confidence == 0.0:
            warnings.append("hypothesis carries zero confidence")
        if hypothesis.model_attribution is None:
            warnings.append("model hypothesis has no attribution record")
        else:
            attribution = hypothesis.model_attribution
            if attribution.context_hash != packet.context_hash:
                errors.append("model attribution context hash does not match the packet")
            if attribution.prompt_version != packet.prompt_version:
                errors.append("model attribution prompt version does not match the packet")

        return HypothesisValidation(
            hypothesis_id=hypothesis.hypothesis_id,
            valid=not errors,
            errors=tuple(errors),
            warnings=tuple(warnings),
            checked_at=moment,
        )
