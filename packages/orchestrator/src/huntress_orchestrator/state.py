"""Explicit, auditable engagement lifecycle transitions.

The controller never assigns ``engagement.state`` directly. Every edge goes
through this table, produces a durable ``StateTransition`` record, and is
mirrored to the append-only audit chain by the controller.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime

from huntress_contracts import (
    ActorType,
    Checkpoint,
    Engagement,
    EngagementState,
    StateTransition,
    ensure_utc,
    new_id,
    utc_now,
)
from huntress_governance import HuntressError

TERMINAL_STATES: frozenset[EngagementState] = frozenset(
    {
        EngagementState.CLOSED,
        EngagementState.CANCELLED,
        EngagementState.FAILED,
    }
)

RECOVERABLE_STATES: frozenset[EngagementState] = frozenset({EngagementState.BLOCKED})

TRANSITION_TABLE: Mapping[EngagementState, frozenset[EngagementState]] = {
    EngagementState.CREATED: frozenset(
        {
            EngagementState.SCOPE_PENDING,
            EngagementState.CANCELLED,
            EngagementState.FAILED,
        }
    ),
    EngagementState.SCOPE_PENDING: frozenset(
        {
            EngagementState.READY,
            EngagementState.CANCELLED,
            EngagementState.FAILED,
        }
    ),
    EngagementState.READY: frozenset(
        {
            EngagementState.RECON,
            EngagementState.ANALYSIS,
            EngagementState.ACTION_PENDING,
            EngagementState.WAITING_FOR_APPROVAL,
            EngagementState.VALIDATING,
            EngagementState.HUMAN_REVIEW,
            EngagementState.REPORT_DRAFT,
            EngagementState.CLOSED,
            EngagementState.BLOCKED,
            EngagementState.CANCELLED,
            EngagementState.FAILED,
        }
    ),
    EngagementState.RECON: frozenset(
        {
            EngagementState.READY,
            EngagementState.ANALYSIS,
            EngagementState.ACTION_PENDING,
            EngagementState.WAITING_FOR_APPROVAL,
            EngagementState.BLOCKED,
            EngagementState.CANCELLED,
            EngagementState.FAILED,
        }
    ),
    EngagementState.ANALYSIS: frozenset(
        {
            EngagementState.READY,
            EngagementState.RECON,
            EngagementState.ACTION_PENDING,
            EngagementState.WAITING_FOR_APPROVAL,
            EngagementState.VALIDATING,
            EngagementState.HUMAN_REVIEW,
            EngagementState.REPORT_DRAFT,
            EngagementState.CLOSED,
            EngagementState.BLOCKED,
            EngagementState.CANCELLED,
            EngagementState.FAILED,
        }
    ),
    EngagementState.ACTION_PENDING: frozenset(
        {
            EngagementState.READY,
            EngagementState.EXECUTING,
            EngagementState.WAITING_FOR_APPROVAL,
            EngagementState.ANALYSIS,
            EngagementState.BLOCKED,
            EngagementState.CANCELLED,
            EngagementState.FAILED,
        }
    ),
    EngagementState.WAITING_FOR_APPROVAL: frozenset(
        {
            EngagementState.READY,
            EngagementState.ACTION_PENDING,
            EngagementState.ANALYSIS,
            EngagementState.BLOCKED,
            EngagementState.CANCELLED,
            EngagementState.FAILED,
        }
    ),
    EngagementState.EXECUTING: frozenset(
        {
            EngagementState.ANALYSIS,
            EngagementState.VALIDATING,
            EngagementState.HUMAN_REVIEW,
            EngagementState.BLOCKED,
            EngagementState.CANCELLED,
            EngagementState.FAILED,
        }
    ),
    EngagementState.VALIDATING: frozenset(
        {
            EngagementState.ANALYSIS,
            EngagementState.HUMAN_REVIEW,
            EngagementState.REPORT_DRAFT,
            EngagementState.BLOCKED,
            EngagementState.CANCELLED,
            EngagementState.FAILED,
        }
    ),
    EngagementState.HUMAN_REVIEW: frozenset(
        {
            EngagementState.ANALYSIS,
            EngagementState.VALIDATING,
            EngagementState.REPORT_DRAFT,
            EngagementState.CLOSED,
            EngagementState.BLOCKED,
            EngagementState.CANCELLED,
            EngagementState.FAILED,
        }
    ),
    EngagementState.REPORT_DRAFT: frozenset(
        {
            EngagementState.ANALYSIS,
            EngagementState.HUMAN_REVIEW,
            EngagementState.SUBMISSION_PENDING,
            EngagementState.CLOSED,
            EngagementState.BLOCKED,
            EngagementState.CANCELLED,
            EngagementState.FAILED,
        }
    ),
    EngagementState.SUBMISSION_PENDING: frozenset(
        {
            EngagementState.REPORT_DRAFT,
            EngagementState.CLOSED,
            EngagementState.BLOCKED,
            EngagementState.CANCELLED,
            EngagementState.FAILED,
        }
    ),
    EngagementState.BLOCKED: frozenset(
        {
            EngagementState.READY,
            EngagementState.ANALYSIS,
            EngagementState.CLOSED,
            EngagementState.CANCELLED,
            EngagementState.FAILED,
        }
    ),
    EngagementState.CLOSED: frozenset(),
    EngagementState.CANCELLED: frozenset(),
    EngagementState.FAILED: frozenset(),
}


class StateTransitionError(HuntressError):
    """A lifecycle edge is not permitted by the explicit state machine."""


def is_terminal(state: EngagementState) -> bool:
    return state in TERMINAL_STATES


def can_transition(from_state: EngagementState, to_state: EngagementState) -> bool:
    return to_state in TRANSITION_TABLE.get(from_state, frozenset())


class StateMachine:
    """Validate edges and build immutable transition/checkpoint records."""

    def require(self, from_state: EngagementState, to_state: EngagementState) -> None:
        if from_state is to_state:
            raise StateTransitionError(f"engagement is already {from_state.value}")
        if not can_transition(from_state, to_state):
            raise StateTransitionError(
                f"transition {from_state.value} -> {to_state.value} is not permitted"
            )

    def transition(
        self,
        engagement: Engagement,
        to_state: EngagementState,
        *,
        reason: str,
        actor_type: ActorType,
        actor_id: str,
        correlation_id: str | None = None,
        now: datetime | None = None,
    ) -> tuple[Engagement, StateTransition]:
        moment = ensure_utc(now) if now is not None else utc_now()
        from_state = engagement.state
        self.require(from_state, to_state)
        if not reason.strip():
            raise StateTransitionError("a state transition requires a reason")

        terminal = is_terminal(to_state)
        updates: dict[str, object] = {
            "state": to_state,
            "updated_at": moment,
            "closed_at": moment if terminal else None,
            "terminal_reason": reason.strip()[:200],
        }
        # Leaving BLOCKED clears the old reason; entering a non-blocked state
        # without a terminal reason also clears it.
        if to_state is not EngagementState.BLOCKED and not terminal:
            updates["terminal_reason"] = None
        updated = Engagement.model_validate({**engagement.model_dump(mode="python"), **updates})
        transition = StateTransition(
            transition_id=new_id("trn"),
            engagement_id=engagement.engagement_id,
            from_state=from_state,
            to_state=to_state,
            reason=reason.strip()[:1000],
            actor_type=actor_type,
            actor_id=actor_id,
            occurred_at=moment,
            correlation_id=(correlation_id or new_id("corr"))[:120],
        )
        return updated, transition

    def checkpoint(
        self,
        engagement: Engagement,
        *,
        correlation_id: str,
        payload: Mapping[str, str | int | float | bool] | None = None,
        note: str = "",
        now: datetime | None = None,
    ) -> Checkpoint:
        moment = ensure_utc(now) if now is not None else utc_now()
        return Checkpoint(
            checkpoint_id=new_id("ckpt"),
            engagement_id=engagement.engagement_id,
            state=engagement.state,
            created_at=moment,
            correlation_id=correlation_id[:120],
            payload=dict(payload or {}),
            note=note[:1000],
        )
