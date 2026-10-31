"""Side-effect-aware reproduction policy.

Repetition is a confirmation tool, not a ritual. Side-effecting actions are
never repeated mechanically to satisfy a counter; differential evidence gets
more trials because noise is the main false-positive source.
"""

from __future__ import annotations

from dataclasses import dataclass

from huntress_contracts import (
    BugClass,
    GateStatus,
    ReproductionPolicyResult,
    SideEffectClass,
    side_effect_rank,
)

_DIFFERENTIAL_TRIALS = 3
_DEFAULT_TRIALS = 1
_STATE_CHANGE_TRIALS = 2


@dataclass(frozen=True, slots=True)
class ReproductionEvidence:
    """Deterministic record of how many independent confirmations were performed."""

    performed_repetitions: int
    independent_confirmation: bool = True
    notes: str = ""


@dataclass(frozen=True, slots=True)
class ReproductionOutcome:
    result: ReproductionPolicyResult
    gate_status: GateStatus
    reason: str


class ReproductionPolicy:
    """Fixed policy keyed by oracle archetype and side-effect class."""

    def required_repetitions(self, bug_class: BugClass, side_effect: SideEffectClass) -> int:
        if side_effect_rank(side_effect) >= side_effect_rank(SideEffectClass.MATERIAL):
            return 1
        if bug_class.oracle_archetype.value == "differential_statistical":
            return _DIFFERENTIAL_TRIALS
        if bug_class.oracle_archetype.value == "state_change_authz":
            return _STATE_CHANGE_TRIALS
        return _DEFAULT_TRIALS

    def evaluate(
        self,
        *,
        bug_class: BugClass,
        side_effect: SideEffectClass,
        evidence: ReproductionEvidence,
        policy_id: str = "huntress-reproduction/1.0",
    ) -> ReproductionOutcome:
        required = self.required_repetitions(bug_class, side_effect)
        performed = max(0, min(evidence.performed_repetitions, 10))
        clamped = min(performed, required)
        side_effecting = side_effect_rank(side_effect) >= side_effect_rank(SideEffectClass.MATERIAL)

        if side_effecting and performed > 1:
            result = ReproductionPolicyResult(
                policy_id=policy_id,
                required_repetitions=1,
                performed_repetitions=1,
                status=GateStatus.FAIL,
                reason=(
                    "side-effecting action was repeated; mechanical repetition of material or "
                    "destructive actions is forbidden"
                ),
                side_effect_class=side_effect.value,
            )
            return ReproductionOutcome(
                result=result,
                gate_status=GateStatus.FAIL,
                reason=result.reason,
            )

        if performed < required:
            result = ReproductionPolicyResult(
                policy_id=policy_id,
                required_repetitions=required,
                performed_repetitions=clamped,
                status=GateStatus.INCONCLUSIVE,
                reason=(
                    f"{required} independent confirmation(s) required for "
                    f"{bug_class.oracle_archetype.value}; {performed} performed"
                ),
                side_effect_class=side_effect.value,
            )
            return ReproductionOutcome(
                result=result,
                gate_status=GateStatus.INCONCLUSIVE,
                reason=result.reason,
            )

        if required > 1 and not evidence.independent_confirmation:
            result = ReproductionPolicyResult(
                policy_id=policy_id,
                required_repetitions=required,
                performed_repetitions=clamped,
                status=GateStatus.INCONCLUSIVE,
                reason="repetitions were not independently confirmed",
                side_effect_class=side_effect.value,
            )
            return ReproductionOutcome(
                result=result,
                gate_status=GateStatus.INCONCLUSIVE,
                reason=result.reason,
            )

        note = f"; {evidence.notes}" if evidence.notes else ""
        result = ReproductionPolicyResult(
            policy_id=policy_id,
            required_repetitions=required,
            performed_repetitions=clamped,
            status=GateStatus.PASS,
            reason=(
                f"{performed} confirmation(s) satisfy the {required}-trial policy for "
                f"{bug_class.oracle_archetype.value}{note}"
            )[:2000],
            side_effect_class=side_effect.value,
        )
        return ReproductionOutcome(
            result=result,
            gate_status=GateStatus.PASS,
            reason=result.reason,
        )


DEFAULT_REPRODUCTION_POLICY = ReproductionPolicy()
