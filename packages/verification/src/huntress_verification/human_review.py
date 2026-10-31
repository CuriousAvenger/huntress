"""Durable human-review decisions.

Only a passed, non-duplicate finding may be approved. Every decision is kept
as an append-only ``HumanReviewRecord``; the finding's review fields are a
projection of the latest record so reporting can check approval cheaply.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime

from huntress_contracts import (
    Actor,
    ActorType,
    AuditEvent,
    DuplicateStatus,
    GateStatus,
    HumanReviewRecord,
    HumanReviewStatus,
    ValidatedFinding,
    ValidationStatus,
    ensure_utc,
    new_id,
    utc_now,
)

from .errors import ReviewDenied, VerificationError
from .models import AuditSink, ReviewOutcome, ReviewStore, ValidationStore

logger = logging.getLogger(__name__)

_ALLOWED_DECISIONS = frozenset(
    {
        HumanReviewStatus.APPROVED,
        HumanReviewStatus.REJECTED,
        HumanReviewStatus.NEEDS_MORE_EVIDENCE,
    }
)


class HumanReviewService:
    """Record reviewer decisions and project them onto validated findings."""

    def __init__(
        self,
        *,
        validations: ValidationStore,
        reviews: ReviewStore,
        audit: AuditSink | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._validations = validations
        self._reviews = reviews
        self._audit = audit
        self._clock = clock

    def review(
        self,
        *,
        finding_id: str,
        reviewer: str,
        decision: HumanReviewStatus,
        notes: str = "",
        evidence_refs: tuple[str, ...] = (),
        now: datetime | None = None,
    ) -> ReviewOutcome:
        moment = ensure_utc(now) if now is not None else ensure_utc(self._clock())
        reviewer = reviewer.strip()
        if not reviewer:
            raise ReviewDenied("reviewer identity is required")
        if decision not in _ALLOWED_DECISIONS:
            raise ReviewDenied("review decision must be approved, rejected, or needs_more_evidence")

        finding = self._validations.get(finding_id)
        if finding is None:
            raise ReviewDenied(f"unknown finding: {finding_id}")
        if decision is HumanReviewStatus.APPROVED:
            self._require_approvable(finding)
            if finding.human_review_status is HumanReviewStatus.APPROVED:
                raise ReviewDenied("finding is already approved")

        refs = evidence_refs or finding.evidence_refs
        outside = sorted(set(refs) - set(finding.evidence_refs))
        if outside:
            raise ReviewDenied(
                "review cites evidence outside the validated finding: " + ", ".join(outside[:5])
            )

        record = HumanReviewRecord(
            review_id=new_id("rev"),
            engagement_id=finding.engagement_id,
            finding_id=finding.finding_id,
            reviewer=reviewer,
            decision=decision,
            notes=notes,
            reviewed_at=moment,
            evidence_refs=tuple(dict.fromkeys(refs)),
        )
        updated = ValidatedFinding.model_validate(
            {
                **finding.model_dump(mode="python"),
                "human_review_status": decision,
                "reviewer": reviewer,
                "reviewed_at": moment,
                "review_notes": notes,
            }
        )

        try:
            self._reviews.save(record)
            self._validations.save(updated)
        except Exception as exc:
            logger.exception("failed to persist review for %s", finding_id)
            raise VerificationError(f"failed to persist human review: {exc}") from exc

        self._audit_review(record=record, finding=updated, moment=moment)
        return ReviewOutcome(review=record, finding=updated)

    def history(self, finding_id: str) -> tuple[HumanReviewRecord, ...]:
        return tuple(self._reviews.list_for_finding(finding_id))

    def require_approved(self, finding_id: str) -> ValidatedFinding:
        """Return an approved finding or refuse the reporting transition."""

        finding = self._validations.get(finding_id)
        if finding is None:
            raise ReviewDenied(f"unknown finding: {finding_id}")
        if finding.status is not ValidationStatus.PASSED:
            raise ReviewDenied(f"finding {finding_id} is not validated: {finding.status.value}")
        if finding.human_review_status is not HumanReviewStatus.APPROVED:
            raise ReviewDenied(
                f"finding {finding_id} requires human approval "
                f"(current: {finding.human_review_status.value})"
            )
        return finding

    @staticmethod
    def _require_approvable(finding: ValidatedFinding) -> None:
        if finding.status is not ValidationStatus.PASSED:
            raise ReviewDenied(
                f"only a passed finding can be approved (current: {finding.status.value})"
            )
        if finding.dedup.status is DuplicateStatus.DUPLICATE:
            raise ReviewDenied("a duplicate finding cannot be approved")
        failed = [gate.gate.value for gate in finding.gates if gate.status is not GateStatus.PASS]
        if failed:
            raise ReviewDenied("finding has non-passing gates: " + ", ".join(failed))

    def _audit_review(
        self, *, record: HumanReviewRecord, finding: ValidatedFinding, moment: datetime
    ) -> None:
        if self._audit is None:
            return
        event = AuditEvent(
            event_id=new_id("aud"),
            occurred_at=moment,
            engagement_id=record.engagement_id,
            actor=Actor(type=ActorType.OPERATOR, id=record.reviewer),
            action="human_review",
            outcome=record.decision.value,
            correlation_id=record.finding_id,
            details={
                "review_id": record.review_id,
                "finding_status": finding.status.value,
                "dedup_status": finding.dedup.status.value,
                "evidence_count": len(record.evidence_refs),
                "notes_length": len(record.notes),
            },
        )
        self._audit.append(event)
