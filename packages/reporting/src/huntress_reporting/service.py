"""Durable report lifecycle with a mandatory human submission gate."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Protocol

from huntress_contracts import (
    Actor,
    ActorType,
    AuditEvent,
    DuplicateStatus,
    GateStatus,
    HumanReviewStatus,
    ReportStatus,
    SubmissionApproval,
    ValidatedFinding,
    ValidationStatus,
    VulnerabilityReport,
    ensure_utc,
    new_id,
    utc_now,
)

from .builder import report_content_hash
from .errors import ReportNotReady, SubmissionDenied, UnknownReport


class ReportStore(Protocol):
    def save(self, report: VulnerabilityReport) -> VulnerabilityReport: ...

    def get(self, report_id: str) -> VulnerabilityReport | None: ...

    def list_by_engagement(self, engagement_id: str) -> list[VulnerabilityReport]: ...


class FindingSource(Protocol):
    def get(self, finding_id: str) -> ValidatedFinding | None: ...


class AuditSink(Protocol):
    def append(self, event: AuditEvent) -> AuditEvent: ...


class ReportService:
    """Persist drafts and enforce approval before any submitted state."""

    def __init__(
        self,
        *,
        reports: ReportStore,
        findings: FindingSource,
        audit: AuditSink | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._reports = reports
        self._findings = findings
        self._audit = audit
        self._clock = clock

    def save_draft(self, report: VulnerabilityReport) -> VulnerabilityReport:
        if report.status is not ReportStatus.DRAFT:
            raise ReportNotReady("only a draft can be saved as a new report")
        self._require_hash(report)
        self._reports.save(report)
        self._emit(
            report=report,
            action="report_draft",
            outcome=report.status.value,
            moment=report.generated_at,
        )
        return report

    def request_approval(self, *, report_id: str, now: datetime | None = None) -> VulnerabilityReport:
        report = self._require(report_id)
        if report.status is not ReportStatus.DRAFT:
            raise ReportNotReady(f"only a draft can request approval (current: {report.status.value})")
        self._require_hash(report)
        moment = self._moment(now)
        updated = VulnerabilityReport.model_validate(
            {**report.model_dump(mode="python"), "status": ReportStatus.PENDING_APPROVAL}
        )
        self._reports.save(updated)
        self._emit(
            report=updated,
            action="report_submission_requested",
            outcome=updated.status.value,
            moment=moment,
        )
        return updated

    def approve_submission(
        self,
        *,
        report_id: str,
        approved_by: str,
        destination: str,
        note: str = "",
        now: datetime | None = None,
    ) -> VulnerabilityReport:
        report = self._require(report_id)
        if report.status not in {ReportStatus.DRAFT, ReportStatus.PENDING_APPROVAL}:
            raise SubmissionDenied(f"report is not awaiting approval (current: {report.status.value})")
        approver = approved_by.strip()
        if not approver:
            raise SubmissionDenied("a named human approver is required")
        target = destination.strip()
        if not target or target == "none":
            raise SubmissionDenied("a concrete submission destination is required")
        if report.destination == "none":
            raise SubmissionDenied("report has no declared destination")
        if target != report.destination:
            raise SubmissionDenied("approval destination does not match the report destination")
        self._require_hash(report)
        self._require_findings_approved(report)

        moment = self._moment(now)
        approval = SubmissionApproval(
            approval_id=new_id("sub"),
            report_id=report.report_id,
            report_content_hash=report.content_hash,
            destination=target,
            approved_by=approver,
            approved_at=moment,
            note=note,
        )
        updated = VulnerabilityReport.model_validate(
            {
                **report.model_dump(mode="python"),
                "status": ReportStatus.APPROVED,
                "approval": approval,
            }
        )
        self._reports.save(updated)
        self._emit(
            report=updated,
            action="report_submission_approved",
            outcome=updated.status.value,
            moment=moment,
            details={"approval_id": approval.approval_id, "destination": target[:500]},
        )
        return updated

    def mark_submitted(self, *, report_id: str, now: datetime | None = None) -> VulnerabilityReport:
        report = self._require(report_id)
        if report.status is not ReportStatus.APPROVED:
            raise SubmissionDenied(f"report is not approved for submission (current: {report.status.value})")
        approval = report.approval
        if approval is None:
            raise SubmissionDenied("approved report has no submission approval")
        self._require_hash(report)
        if approval.report_id != report.report_id:
            raise SubmissionDenied("submission approval belongs to a different report")
        if approval.report_content_hash != report.content_hash:
            raise SubmissionDenied("submission approval does not match report content")
        if approval.destination != report.destination:
            raise SubmissionDenied("submission approval destination changed")
        self._require_findings_approved(report)

        moment = self._moment(now)
        updated = VulnerabilityReport.model_validate(
            {**report.model_dump(mode="python"), "status": ReportStatus.SUBMITTED}
        )
        self._reports.save(updated)
        self._emit(
            report=updated,
            action="report_submitted",
            outcome=updated.status.value,
            moment=moment,
            details={"approval_id": approval.approval_id},
        )
        return updated

    def withdraw(self, *, report_id: str, reason: str, now: datetime | None = None) -> VulnerabilityReport:
        report = self._require(report_id)
        if report.status is ReportStatus.SUBMITTED:
            raise SubmissionDenied("a submitted report cannot be withdrawn locally")
        if not reason.strip():
            raise SubmissionDenied("withdrawal reason is required")
        self._require_hash(report)
        moment = self._moment(now)
        updated = VulnerabilityReport.model_validate(
            {**report.model_dump(mode="python"), "status": ReportStatus.WITHDRAWN}
        )
        self._reports.save(updated)
        self._emit(
            report=updated,
            action="report_withdrawn",
            outcome=updated.status.value,
            moment=moment,
            details={"reason": reason[:1000]},
        )
        return updated

    def get(self, report_id: str) -> VulnerabilityReport | None:
        return self._reports.get(report_id)

    def list_by_engagement(self, engagement_id: str) -> tuple[VulnerabilityReport, ...]:
        return tuple(self._reports.list_by_engagement(engagement_id))

    def _require(self, report_id: str) -> VulnerabilityReport:
        report = self._reports.get(report_id)
        if report is None:
            raise UnknownReport(f"unknown report: {report_id}")
        return report

    @staticmethod
    def _require_hash(report: VulnerabilityReport) -> None:
        if report_content_hash(report) != report.content_hash:
            raise SubmissionDenied("report content hash does not match its current content")

    def _require_findings_approved(self, report: VulnerabilityReport) -> None:
        for finding_id in report.finding_ids:
            finding = self._findings.get(finding_id)
            if finding is None:
                raise SubmissionDenied(f"report references unknown finding {finding_id}")
            if finding.engagement_id != report.engagement_id:
                raise SubmissionDenied(f"finding {finding_id} belongs to another engagement")
            if finding.status is not ValidationStatus.PASSED:
                raise SubmissionDenied(f"finding {finding_id} is no longer passed")
            if finding.dedup.status is DuplicateStatus.DUPLICATE:
                raise SubmissionDenied(f"finding {finding_id} is now a duplicate")
            if finding.human_review_status is not HumanReviewStatus.APPROVED:
                raise SubmissionDenied(
                    f"finding {finding_id} is not human-approved "
                    f"(current: {finding.human_review_status.value})"
                )
            if any(gate.status is not GateStatus.PASS for gate in finding.gates):
                raise SubmissionDenied(f"finding {finding_id} has non-passing gates")
            if not set(finding.evidence_refs).issubset(set(report.evidence_refs)):
                raise SubmissionDenied(f"finding {finding_id} has evidence not preserved in the report")

    def _moment(self, now: datetime | None) -> datetime:
        return ensure_utc(now) if now is not None else ensure_utc(self._clock())

    def _emit(
        self,
        *,
        report: VulnerabilityReport,
        action: str,
        outcome: str,
        moment: datetime,
        details: dict[str, str | int | float | bool] | None = None,
    ) -> None:
        if self._audit is None:
            return
        self._audit.append(
            AuditEvent(
                event_id=new_id("aud"),
                occurred_at=moment,
                engagement_id=report.engagement_id,
                actor=Actor(type=ActorType.OPERATOR, id="reporting-service"),
                action=action,
                outcome=outcome[:80],
                correlation_id=report.report_id,
                details={
                    "finding_count": len(report.finding_ids),
                    "status": report.status.value,
                    **(details or {}),
                },
            )
        )
