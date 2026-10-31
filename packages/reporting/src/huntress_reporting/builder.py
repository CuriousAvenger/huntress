"""Deterministic report drafting from validated findings only."""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import datetime

from huntress_contracts import (
    DuplicateStatus,
    GateStatus,
    HumanReviewStatus,
    ReportStatus,
    SeverityBand,
    ValidatedFinding,
    ValidationStatus,
    VulnerabilityReport,
    content_hash,
    ensure_utc,
    get_bug_class,
    new_id,
    utc_now,
)

from .errors import ReportNotReady

_ARTIFACT_REF = re.compile(r"^[0-9a-f]{64}$")
_SEVERITY_ORDER = {
    SeverityBand.INFO: 0,
    SeverityBand.LOW: 1,
    SeverityBand.MEDIUM: 2,
    SeverityBand.HIGH: 3,
    SeverityBand.CRITICAL: 4,
    SeverityBand.UNKNOWN: -1,
}
_HASH_EXCLUDED_FIELDS = frozenset({"content_hash", "approval", "status", "content_ref"})


def report_content_hash(report: VulnerabilityReport) -> str:
    """Hash only stable report content, not workflow fields or approval."""

    data = report.model_dump(mode="json")
    for field in _HASH_EXCLUDED_FIELDS:
        data.pop(field, None)
    return content_hash(data)


class ReportBuilder:
    """Build one report draft from one or more approved-for-drafting findings."""

    def build(
        self,
        *,
        findings: Sequence[ValidatedFinding],
        reproduction_steps: Sequence[str],
        title: str | None = None,
        summary: str | None = None,
        impact: str | None = None,
        remediation: str = "",
        references: Sequence[str] = (),
        disclosure: str = "Coordinated disclosure.",
        platform: str = "none",
        destination: str = "none",
        redaction_status: str = "redacted",
        content_ref: str | None = None,
        now: datetime | None = None,
    ) -> VulnerabilityReport:
        records = tuple(findings)
        self._validate_findings(records)
        steps = tuple(step.strip() for step in reproduction_steps if step.strip())
        if not steps:
            raise ReportNotReady("a report requires at least one reproduction step")

        moment = ensure_utc(now) if now is not None else ensure_utc(utc_now())
        engagement_id = records[0].engagement_id
        evidence_refs = tuple(dict.fromkeys(ref for finding in records for ref in finding.evidence_refs))
        resolved_title = (title or self._default_title(records)).strip()
        resolved_summary = (summary or self._default_summary(records)).strip()
        resolved_impact = (impact or self._default_impact(records)).strip()
        if not resolved_title:
            raise ReportNotReady("report title must not be empty")
        if not resolved_summary:
            raise ReportNotReady("report summary must not be empty")
        if not resolved_impact:
            raise ReportNotReady("report impact must not be empty")
        resolved_references = tuple(dict.fromkeys((*references, *self._cwe_references(records))))

        draft = VulnerabilityReport(
            report_id=new_id("rpt"),
            engagement_id=engagement_id,
            finding_ids=tuple(finding.finding_id for finding in records),
            title=resolved_title[:300],
            summary=resolved_summary[:4000],
            impact=resolved_impact[:8000],
            reproduction_steps=steps,
            evidence_refs=evidence_refs,
            remediation=remediation.strip()[:4000],
            references=resolved_references,
            disclosure=disclosure.strip()[:2000] or "Coordinated disclosure.",
            platform=platform.strip()[:80] or "none",
            destination=destination.strip()[:500] or "none",
            status=ReportStatus.DRAFT,
            generated_at=moment,
            content_hash="0" * 64,
            content_ref=content_ref,
            redaction_status=redaction_status.strip()[:40] or "redacted",
        )
        digest = report_content_hash(draft)
        return VulnerabilityReport.model_validate({**draft.model_dump(mode="python"), "content_hash": digest})

    @staticmethod
    def _validate_findings(findings: tuple[ValidatedFinding, ...]) -> None:
        if not findings:
            raise ReportNotReady("a report requires at least one validated finding")
        engagement_id = findings[0].engagement_id
        seen: set[str] = set()
        for finding in findings:
            if finding.finding_id in seen:
                raise ReportNotReady(f"duplicate finding in report: {finding.finding_id}")
            seen.add(finding.finding_id)
            if finding.engagement_id != engagement_id:
                raise ReportNotReady("all report findings must belong to one engagement")
            if finding.status is not ValidationStatus.PASSED:
                raise ReportNotReady(f"finding {finding.finding_id} is {finding.status.value}, not passed")
            if finding.dedup.status is DuplicateStatus.DUPLICATE:
                raise ReportNotReady(f"finding {finding.finding_id} is a duplicate")
            non_passing = [gate.gate.value for gate in finding.gates if gate.status is not GateStatus.PASS]
            if non_passing:
                raise ReportNotReady(
                    f"finding {finding.finding_id} has non-passing gates: " + ", ".join(non_passing)
                )
            if finding.human_review_status in {
                HumanReviewStatus.REJECTED,
                HumanReviewStatus.NEEDS_MORE_EVIDENCE,
            }:
                raise ReportNotReady(
                    f"finding {finding.finding_id} was not approved for reporting "
                    f"({finding.human_review_status.value})"
                )
            for ref in finding.evidence_refs:
                if not _ARTIFACT_REF.fullmatch(ref):
                    raise ReportNotReady(f"finding {finding.finding_id} has a malformed evidence ref")

    @staticmethod
    def _default_title(findings: tuple[ValidatedFinding, ...]) -> str:
        if len(findings) == 1:
            return findings[0].title
        return f"{len(findings)} validated findings: {findings[0].title}"

    @staticmethod
    def _default_summary(findings: tuple[ValidatedFinding, ...]) -> str:
        lines = []
        for finding in findings:
            lines.append(f"[{finding.severity.band.value.upper()}] {finding.title}: {finding.claim}")
        return "\n\n".join(lines)

    @staticmethod
    def _default_impact(findings: tuple[ValidatedFinding, ...]) -> str:
        ranked = max(
            findings,
            key=lambda finding: _SEVERITY_ORDER[finding.severity.band],
        )
        impact = ranked.severity.impact_summary
        if ranked.severity.uncertainty:
            impact += f"\n\nUncertainty: {ranked.severity.uncertainty}"
        return impact

    @staticmethod
    def _cwe_references(findings: tuple[ValidatedFinding, ...]) -> tuple[str, ...]:
        refs: list[str] = []
        for finding in findings:
            try:
                bug_class = get_bug_class(finding.bug_class_id)
            except KeyError:  # pragma: no cover - validated findings use known classes
                continue
            refs.append(f"https://cwe.mitre.org/data/definitions/{bug_class.cwe_id}.html")
        return tuple(dict.fromkeys(refs))
