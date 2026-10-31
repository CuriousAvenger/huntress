"""Typed reporting and submission failures."""

from __future__ import annotations


class ReportingError(Exception):
    """Base class for deterministic reporting failures."""


class ReportNotReady(ReportingError):
    """A validated finding does not meet the report-draft preconditions."""


class UnknownReport(ReportingError):
    """The requested report id does not exist."""


class SubmissionDenied(ReportingError):
    """A submission transition lacks valid human approval or current evidence."""
