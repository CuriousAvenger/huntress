"""Budget arithmetic and transactional reservation ports.

The gateway performs a cheap snapshot check; the execution service performs an
atomic reservation. Both use the same arithmetic. A crash between reservation
and execution leaves a reserved hold that the controller releases on recovery.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from huntress_contracts import (
    BudgetLimits,
    BudgetReservation,
    BudgetSnapshot,
    BudgetUsage,
    HostRequestCount,
    ReasonCode,
    ensure_utc,
)

from .errors import BudgetExceeded


class BudgetStore(Protocol):
    """Persistence port implemented by the SQLite repository."""

    def get_usage(self, engagement_id: str) -> BudgetUsage: ...

    def reserve(
        self,
        engagement_id: str,
        limits: BudgetLimits,
        reservation: BudgetReservation,
    ) -> BudgetReservation: ...

    def commit(
        self,
        reservation_id: str,
        *,
        actions: int | None = None,
        tokens: int | None = None,
        cost_usd: float | None = None,
    ) -> None: ...

    def release(self, reservation_id: str) -> None: ...

    def get_reservation(self, reservation_id: str) -> BudgetReservation | None: ...


class BudgetManager:
    """Pure budget math plus delegation to the transactional store."""

    def __init__(self, store: BudgetStore) -> None:
        self._store = store

    def snapshot(self, engagement_id: str, limits: BudgetLimits, now: datetime) -> BudgetSnapshot:
        usage = self._store.get_usage(engagement_id)
        return self.build_snapshot(limits, usage, now)

    @staticmethod
    def build_snapshot(limits: BudgetLimits, usage: BudgetUsage, now: datetime) -> BudgetSnapshot:
        moment = ensure_utc(now)
        return BudgetSnapshot(
            limits=limits,
            usage=usage,
            remaining_actions=max(0, limits.max_actions - usage.actions_used),
            remaining_model_calls=max(0, limits.max_model_calls - usage.model_calls_used),
            remaining_tokens=max(0, limits.max_tokens - usage.tokens_used),
            remaining_cost_usd=max(0.0, limits.max_cost_usd - usage.cost_usd_used),
            remaining_wall_clock_seconds=max(
                0, limits.max_wall_clock_seconds - usage.wall_clock_seconds_used
            ),
            captured_at=moment,
        )

    @staticmethod
    def check(
        snapshot: BudgetSnapshot,
        *,
        host: str,
        requests: int = 1,
        actions: int = 1,
        model_calls: int = 0,
        tokens: int = 0,
        cost_usd: float = 0.0,
    ) -> tuple[ReasonCode | None, tuple[str, ...]]:
        reasons: list[str] = []
        if actions > snapshot.remaining_actions:
            reasons.append(f"action budget exhausted: need {actions}, remaining {snapshot.remaining_actions}")
        if model_calls > snapshot.remaining_model_calls:
            reasons.append(
                f"model-call budget exhausted: need {model_calls}, remaining {snapshot.remaining_model_calls}"
            )
        if tokens > snapshot.remaining_tokens:
            reasons.append(f"token budget exhausted: need {tokens}, remaining {snapshot.remaining_tokens}")
        if cost_usd > snapshot.remaining_cost_usd + 1e-9:
            reasons.append(
                f"cost budget exhausted: need {cost_usd:.4f}, remaining {snapshot.remaining_cost_usd:.4f}"
            )
        if snapshot.remaining_wall_clock_seconds <= 0:
            reasons.append("wall-clock budget exhausted")

        host_count = next(
            (h.requests for h in snapshot.usage.host_request_counts if h.host == host),
            0,
        )
        if host_count + requests > snapshot.limits.max_requests_per_host_per_minute:
            reasons.append(
                f"host rate limit: {host_count}+{requests} > "
                f"{snapshot.limits.max_requests_per_host_per_minute}/min for {host}"
            )
        if snapshot.usage.requests_total + requests > snapshot.limits.max_requests_per_engagement_per_minute:
            reasons.append(
                f"engagement rate limit: {snapshot.usage.requests_total}+{requests} > "
                f"{snapshot.limits.max_requests_per_engagement_per_minute}/min"
            )
        if reasons:
            code = (
                ReasonCode.DENIED_RATE_LIMITED
                if any("rate limit" in reason for reason in reasons)
                else ReasonCode.DENIED_BUDGET_EXHAUSTED
            )
            return code, tuple(reasons)
        return None, ()

    def reserve(
        self,
        *,
        engagement_id: str,
        limits: BudgetLimits,
        reservation: BudgetReservation,
    ) -> BudgetReservation:
        return self._store.reserve(engagement_id, limits, reservation)

    def commit(
        self,
        reservation_id: str,
        *,
        actions: int | None = None,
        tokens: int | None = None,
        cost_usd: float | None = None,
    ) -> None:
        self._store.commit(reservation_id, actions=actions, tokens=tokens, cost_usd=cost_usd)

    def release(self, reservation_id: str) -> None:
        self._store.release(reservation_id)

    def get_reservation(self, reservation_id: str) -> BudgetReservation | None:
        return self._store.get_reservation(reservation_id)


class InMemoryBudgetStore:
    """Deterministic store for unit tests and the offline evaluator.

    Not used by the CLI. It implements the same reservation semantics as SQLite.
    """

    def __init__(self) -> None:
        self._usage: dict[str, BudgetUsage] = {}
        self._reservations: dict[str, BudgetReservation] = {}
        self._host_counts: dict[tuple[str, str], int] = {}

    def get_usage(self, engagement_id: str) -> BudgetUsage:
        usage = self._usage.get(engagement_id, BudgetUsage())
        hosts = tuple(
            HostRequestCount(host=host, requests=count)
            for (eng, host), count in sorted(self._host_counts.items())
            if eng == engagement_id and count > 0
        )
        return usage.model_copy(update={"host_request_counts": hosts})

    def reserve(
        self,
        engagement_id: str,
        limits: BudgetLimits,
        reservation: BudgetReservation,
    ) -> BudgetReservation:
        usage = self.get_usage(engagement_id)
        if reservation.actions and usage.actions_used + reservation.actions > limits.max_actions:
            raise BudgetExceeded("action budget exhausted")
        if (
            reservation.model_calls
            and usage.model_calls_used + reservation.model_calls > limits.max_model_calls
        ):
            raise BudgetExceeded("model-call budget exhausted")
        if reservation.tokens and usage.tokens_used + reservation.tokens > limits.max_tokens:
            raise BudgetExceeded("token budget exhausted")
        if reservation.cost_usd and usage.cost_usd_used + reservation.cost_usd > limits.max_cost_usd + 1e-9:
            raise BudgetExceeded("cost budget exhausted")
        if reservation.host and reservation.requests:
            key = (engagement_id, reservation.host)
            current = self._host_counts.get(key, 0)
            if current + reservation.requests > limits.max_requests_per_host_per_minute:
                raise BudgetExceeded("host rate limit exceeded", reason_code=ReasonCode.DENIED_RATE_LIMITED)
            self._host_counts[key] = current + reservation.requests
        self._usage[engagement_id] = usage.model_copy(
            update={
                "actions_used": usage.actions_used + reservation.actions,
                "model_calls_used": usage.model_calls_used + reservation.model_calls,
                "tokens_used": usage.tokens_used + reservation.tokens,
                "cost_usd_used": usage.cost_usd_used + reservation.cost_usd,
                "requests_total": usage.requests_total + reservation.requests,
            }
        )
        self._reservations[reservation.reservation_id] = reservation
        return reservation

    def commit(
        self,
        reservation_id: str,
        *,
        actions: int | None = None,
        tokens: int | None = None,
        cost_usd: float | None = None,
    ) -> None:
        reservation = self._reservations.get(reservation_id)
        if reservation is None or reservation.status != "reserved":
            return
        actual_actions = reservation.actions if actions is None else max(0, actions)
        actual_tokens = reservation.tokens if tokens is None else max(0, tokens)
        actual_cost = reservation.cost_usd if cost_usd is None else max(0.0, cost_usd)
        usage = self._usage[reservation.engagement_id]
        self._usage[reservation.engagement_id] = usage.model_copy(
            update={
                "actions_used": max(0, usage.actions_used + actual_actions - reservation.actions),
                "tokens_used": max(0, usage.tokens_used + actual_tokens - reservation.tokens),
                "cost_usd_used": max(0.0, usage.cost_usd_used + actual_cost - reservation.cost_usd),
            }
        )
        self._reservations[reservation_id] = reservation.model_copy(
            update={
                "status": "committed",
                "settled_at": reservation.created_at,
                "actions": actual_actions,
                "tokens": actual_tokens,
                "cost_usd": actual_cost,
            }
        )

    def release(self, reservation_id: str) -> None:
        reservation = self._reservations.get(reservation_id)
        if reservation is None or reservation.status != "reserved":
            return
        usage = self._usage[reservation.engagement_id]
        if reservation.host and reservation.requests:
            key = (reservation.engagement_id, reservation.host)
            self._host_counts[key] = max(0, self._host_counts.get(key, 0) - reservation.requests)
        self._usage[reservation.engagement_id] = usage.model_copy(
            update={
                "actions_used": max(0, usage.actions_used - reservation.actions),
                "model_calls_used": max(0, usage.model_calls_used - reservation.model_calls),
                "tokens_used": max(0, usage.tokens_used - reservation.tokens),
                "cost_usd_used": max(0.0, usage.cost_usd_used - reservation.cost_usd),
                "requests_total": max(0, usage.requests_total - reservation.requests),
            }
        )
        self._reservations[reservation_id] = reservation.model_copy(update={"status": "released"})

    def get_reservation(self, reservation_id: str) -> BudgetReservation | None:
        return self._reservations.get(reservation_id)
