"""Bounded sweep planning and digest assembly."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime

from huntress_contracts import (
    ProfileRunSummary,
    ToolFinding,
    ToolProfile,
    ToolRunResult,
    ToolRunStatus,
    ToolSweepDigest,
    new_id,
    risk_rank,
    utc_now,
)

_WORKSTREAM_ORDER = {
    "passive_osint": 0,
    "active_enumeration": 1,
    "web_surface": 2,
    "signature_check": 3,
    "cve_correlation": 4,
    "detect_only": 5,
    "client_artifact": 6,
    "binary_identity": 7,
}


def order_profiles(
    profile_ids: Iterable[str],
    catalog: Mapping[str, ToolProfile],
) -> tuple[ToolProfile, ...]:
    """Return a deterministic passive-first plan and reject unknown IDs."""

    requested = list(profile_ids)
    if len(requested) != len(set(requested)):
        raise ValueError("profile_ids must be unique")
    missing = sorted(set(requested) - set(catalog))
    if missing:
        raise ValueError(f"unknown profiles: {missing}")
    profiles = [catalog[profile_id] for profile_id in requested]
    return tuple(
        sorted(
            profiles,
            key=lambda profile: (
                risk_rank(profile.risk_class),
                _WORKSTREAM_ORDER.get(profile.workstream.value, 99),
                profile.profile_id,
            ),
        )
    )


def default_profiles(catalog: Mapping[str, ToolProfile]) -> tuple[ToolProfile, ...]:
    return order_profiles(
        (profile.profile_id for profile in catalog.values() if profile.enabled_by_default),
        catalog,
    )


def _aggregate_status(statuses: Iterable[ToolRunStatus]) -> ToolRunStatus:
    values = list(statuses)
    if not values:
        return ToolRunStatus.SKIPPED
    for status in (
        ToolRunStatus.FAILED,
        ToolRunStatus.TIMEOUT,
        ToolRunStatus.BLOCKED,
        ToolRunStatus.CANCELLED,
        ToolRunStatus.SKIPPED,
    ):
        if status in values:
            return status
    return ToolRunStatus.SUCCEEDED


@dataclass
class SweepBuilder:
    """Collect execution results into one immutable sweep digest."""

    engagement_id: str
    scope_hash: str
    started_at: datetime = field(default_factory=utc_now)
    summaries: list[ProfileRunSummary] = field(default_factory=list)
    findings: list[ToolFinding] = field(default_factory=list)
    artifact_refs: list[str] = field(default_factory=list)
    _statuses: list[ToolRunStatus] = field(default_factory=list)

    def add(self, run: ToolRunResult, findings: Iterable[ToolFinding] = ()) -> None:
        materialized = tuple(findings)
        self.summaries.append(
            ProfileRunSummary(
                profile_id=run.profile_id,
                profile_version=run.profile_version,
                target_id=run.target_id,
                status=run.status,
                findings=len(materialized),
                duration_ms=run.duration_ms,
                attempts=1,
                error_code=run.error_code,
                artifact_refs=run.artifact_refs,
            )
        )
        self.findings.extend(materialized)
        self.artifact_refs.extend(run.artifact_refs)
        self._statuses.append(run.status)

    def finish(self, *, notes: str = "", finished_at: datetime | None = None) -> ToolSweepDigest:
        counts = Counter(finding.finding_type for finding in self.findings)
        return ToolSweepDigest(
            sweep_id=new_id("sweep"),
            engagement_id=self.engagement_id,
            started_at=self.started_at,
            finished_at=finished_at or utc_now(),
            status=_aggregate_status(self._statuses),
            scope_hash=self.scope_hash,
            profiles_run=tuple(self.summaries),
            total_findings=len(self.findings),
            finding_counts=dict(sorted(counts.items())),
            artifact_refs=tuple(dict.fromkeys(self.artifact_refs)),
            notes=notes,
        )
