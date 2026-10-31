"""Report-draft and submission-approval contracts.

Reports are derived exclusively from ``ValidatedFinding`` records. A report
draft is not a submission; the submission approval is a separate human record
bound to the exact report content hash.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, field_validator, model_validator

from .base import Contract, ensure_utc
from .enums import ReportStatus


class SubmissionApproval(Contract):
    """Explicit human approval for one report hash and one destination."""

    approval_id: str = Field(pattern=r"^sub_[a-zA-Z0-9_-]{6,80}$")
    report_id: str = Field(pattern=r"^rpt_[a-zA-Z0-9_-]{6,80}$")
    report_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    destination: str = Field(min_length=1, max_length=500)
    approved_by: str = Field(min_length=1, max_length=200)
    approved_at: datetime
    note: str = Field(default="", max_length=2000)

    _approved_utc = field_validator("approved_at")(ensure_utc)


class VulnerabilityReport(Contract):
    """A report draft built from validated evidence references."""

    report_id: str = Field(pattern=r"^rpt_[a-zA-Z0-9_-]{6,80}$")
    engagement_id: str = Field(pattern=r"^eng_[a-zA-Z0-9_-]{6,80}$")
    finding_ids: tuple[str, ...] = Field(min_length=1)
    title: str = Field(min_length=1, max_length=300)
    summary: str = Field(min_length=1, max_length=4000)
    impact: str = Field(min_length=1, max_length=8000)
    reproduction_steps: tuple[str, ...] = Field(min_length=1)
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    remediation: str = Field(default="", max_length=4000)
    references: tuple[str, ...] = ()
    disclosure: str = Field(default="Coordinated disclosure.", max_length=2000)
    platform: str = Field(default="none", max_length=80)
    destination: str = Field(default="none", max_length=500)
    status: ReportStatus = ReportStatus.DRAFT
    generated_at: datetime
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    content_ref: str | None = Field(default=None, max_length=128)
    approval: SubmissionApproval | None = None
    redaction_status: str = Field(default="redacted", max_length=40)

    _generated_utc = field_validator("generated_at")(ensure_utc)

    @model_validator(mode="after")
    def _submission_shape(self) -> VulnerabilityReport:
        if len(set(self.finding_ids)) != len(self.finding_ids):
            raise ValueError("finding_ids must be unique")
        if self.status is ReportStatus.SUBMITTED:
            if self.approval is None:
                raise ValueError("submitted report requires explicit human approval")
            if self.approval.report_id != self.report_id:
                raise ValueError("approval belongs to a different report")
            if self.approval.report_content_hash != self.content_hash:
                raise ValueError("approval does not match report content hash")
        return self
