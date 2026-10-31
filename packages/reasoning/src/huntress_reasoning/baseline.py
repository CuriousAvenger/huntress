"""Deterministic rule-based planner used as the reasoning baseline.

The baseline deliberately has no model access. It proves that the controller
and contracts work end-to-end and gives evaluations a fixed reference point for
measuring whether a model checkpoint adds value.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from huntress_contracts import (
    ActionKind,
    ContextPacket,
    ContextTask,
    DecisionSource,
    InvestigationDecision,
    ensure_utc,
    new_id,
    utc_now,
)

from .errors import TaskMismatch
from .validators import DecisionValidator

_MAX_REVIEW_EVIDENCE = 5


class RuleBasedPlanner:
    """Choose one bounded action from packet state without a model call."""

    def __init__(self, validator: DecisionValidator | None = None) -> None:
        self._validator = validator or DecisionValidator()

    def select_action(
        self,
        packet: ContextPacket,
        *,
        reviewed_evidence_ids: Iterable[str] = (),
        attempted_profile_ids: Iterable[str] = (),
        now: datetime | None = None,
    ) -> InvestigationDecision:
        if packet.task is not ContextTask.ACTION_SELECTION:
            raise TaskMismatch(f"packet task is {packet.task.value}, expected action_selection")
        moment = ensure_utc(now) if now is not None else ensure_utc(utc_now())
        reviewed = set(reviewed_evidence_ids)
        attempted = set(attempted_profile_ids)

        action, target_id, profile_id, hypothesis_id, evidence_ids, rationale = self._choose(
            packet, reviewed=reviewed, attempted=attempted
        )
        decision = InvestigationDecision(
            decision_id=new_id("dec"),
            engagement_id=packet.engagement_id,
            action=action,
            target_id=target_id,
            profile_id=profile_id,
            hypothesis_id=hypothesis_id,
            evidence_ids=evidence_ids,
            rationale_summary=rationale,
            confidence=0.5,
            source=DecisionSource.RULE_ENGINE,
            created_at=moment,
        )
        validation = self._validator.validate(decision, packet, now=moment)
        if not validation.valid:  # pragma: no cover - packet construction is authoritative
            raise ValueError("baseline produced an invalid decision: " + "; ".join(validation.errors))
        return decision

    def _choose(
        self,
        packet: ContextPacket,
        *,
        reviewed: set[str],
        attempted: set[str],
    ) -> tuple[
        ActionKind,
        str | None,
        str | None,
        str | None,
        tuple[str, ...],
        str,
    ]:
        targets = packet.allowed_target_ids
        profiles = packet.allowed_profile_ids
        evidence = packet.allowed_evidence_ids

        if not targets:
            return (
                ActionKind.INSPECT_INVENTORY,
                None,
                None,
                None,
                (),
                "No targets are in the packet; inspect the authorized inventory first.",
            )

        unreviewed = tuple(item for item in evidence if item not in reviewed)
        if unreviewed:
            selected = unreviewed[:_MAX_REVIEW_EVIDENCE]
            return (
                ActionKind.REVIEW_EVIDENCE,
                None,
                None,
                None,
                selected,
                "Review unreviewed evidence before choosing another test.",
            )

        if evidence:
            selected = tuple(evidence[:_MAX_REVIEW_EVIDENCE])
            return (
                ActionKind.REQUEST_HUMAN_REVIEW,
                None,
                None,
                None,
                selected,
                "Evidence exists and has been reviewed; ask a human to decide whether it is reportable.",
            )

        available_profiles = tuple(item for item in profiles if item not in attempted)
        if available_profiles:
            return (
                ActionKind.RUN_APPROVED_PROFILE,
                targets[0],
                available_profiles[0],
                None,
                (),
                "No evidence has been collected yet; run the first unattempted approved profile.",
            )

        if attempted:
            return (
                ActionKind.STOP,
                None,
                None,
                None,
                (),
                "Every allowed profile has been attempted and no evidence remains to review.",
            )

        return (
            ActionKind.STOP,
            None,
            None,
            None,
            (),
            "No approved profile is available for this target; stop rather than improvise.",
        )
