"""Deterministic scope, evidence-completeness, and deduplication gates."""

from __future__ import annotations

import re
from datetime import datetime

from huntress_contracts import (
    BugClass,
    DedupResult,
    DuplicateStatus,
    Engagement,
    EngagementState,
    GateName,
    GateResult,
    GateStatus,
    HttpMethod,
    ScopeDocument,
    TargetRecord,
    ToolFinding,
    ValidatedFinding,
    ensure_utc,
)
from huntress_evidence import ArtifactStore, ArtifactStoreError
from huntress_governance import ScopeGuard

from .fingerprints import evidence_tokens, finding_fingerprint, similarity

_REF_RE = re.compile(r"^[0-9a-f]{64}$")
_TERMINAL_STATES = frozenset(
    {
        EngagementState.CLOSED,
        EngagementState.CANCELLED,
        EngagementState.FAILED,
        EngagementState.BLOCKED,
    }
)


class ScopeGate:
    gate = GateName.SCOPE_RECHECK
    checker_version = "scope/1.0"

    def __init__(self, guard: ScopeGuard | None = None) -> None:
        self._guard = guard or ScopeGuard()

    def evaluate(
        self,
        *,
        engagement: Engagement,
        scope: ScopeDocument,
        target: TargetRecord,
        method: HttpMethod,
        signing_key: bytes,
        now: datetime,
    ) -> GateResult:
        moment = ensure_utc(now)
        if engagement.state in _TERMINAL_STATES:
            return GateResult(
                gate=self.gate,
                status=GateStatus.FAIL,
                reason=f"engagement is terminal: {engagement.state.value}",
                checked_at=moment,
                checker_version=self.checker_version,
            )
        check = self._guard.check_target(
            engagement=engagement,
            scope=scope,
            target=target,
            method=method,
            now=moment,
            signing_key=signing_key,
        )
        if not check.allowed:
            return GateResult(
                gate=self.gate,
                status=GateStatus.FAIL,
                reason="; ".join(check.reasons) or check.reason_code.value,
                checked_at=moment,
                checker_version=self.checker_version,
            )
        return GateResult(
            gate=self.gate,
            status=GateStatus.PASS,
            reason="scope, target, method, window, and seal rechecked",
            evidence_refs=(),
            checked_at=moment,
            checker_version=self.checker_version,
        )


class EvidenceGate:
    gate = GateName.EVIDENCE_COMPLETENESS
    checker_version = "evidence/1.0"

    def evaluate(
        self,
        *,
        engagement: Engagement,
        scope: ScopeDocument,
        target: TargetRecord,
        bug_class: BugClass,
        findings: tuple[ToolFinding, ...],
        store: ArtifactStore,
        now: datetime,
    ) -> tuple[GateResult, tuple[str, ...]]:
        moment = ensure_utc(now)
        if not findings:
            return (
                GateResult(
                    gate=self.gate,
                    status=GateStatus.FAIL,
                    reason="no tool findings support the candidate",
                    checked_at=moment,
                    checker_version=self.checker_version,
                ),
                (),
            )

        refs: set[str] = set()
        problems: list[str] = []
        matched_bug_class = False
        for finding in findings:
            if finding.engagement_id != engagement.engagement_id:
                problems.append(f"{finding.finding_id}: engagement mismatch")
                continue
            if finding.target_id != target.target_id:
                problems.append(f"{finding.finding_id}: target mismatch")
                continue
            if finding.bug_class_id is None:
                problems.append(f"{finding.finding_id}: no canonical bug class")
            elif finding.bug_class_id != bug_class.bug_class_id:
                problems.append(
                    f"{finding.finding_id}: bug class {finding.bug_class_id} does not match "
                    f"{bug_class.bug_class_id}"
                )
            else:
                matched_bug_class = True
            if not scope.testing_window.contains(finding.observed_at):
                problems.append(f"{finding.finding_id}: observed outside the testing window")
            if not finding.artifact_refs:
                problems.append(f"{finding.finding_id}: no artifact references")
                continue
            for ref in finding.artifact_refs:
                if not _REF_RE.fullmatch(ref):
                    problems.append(f"{finding.finding_id}: malformed artifact reference")
                    continue
                if not store.exists(ref):
                    problems.append(f"{finding.finding_id}: artifact {ref[:12]} is missing")
                    continue
                try:
                    if not store.verify(ref):
                        problems.append(f"{finding.finding_id}: artifact failed integrity check")
                        continue
                    metadata = store.metadata(ref)
                except ArtifactStoreError as exc:
                    problems.append(f"{finding.finding_id}: artifact metadata error: {exc}")
                    continue
                if not any(
                    provenance.engagement_id == engagement.engagement_id
                    and provenance.target_id == target.target_id
                    for provenance in metadata.provenance
                ):
                    problems.append(
                        f"{finding.finding_id}: artifact provenance does not match the engagement "
                        "and target"
                    )
                    continue
                refs.add(ref)

        if not matched_bug_class:
            problems.append("no finding carries the candidate's canonical bug class")
        if problems:
            return (
                GateResult(
                    gate=self.gate,
                    status=GateStatus.FAIL,
                    reason="; ".join(problems[:12])[:2000],
                    evidence_refs=tuple(sorted(refs)),
                    checked_at=moment,
                    checker_version=self.checker_version,
                ),
                tuple(sorted(refs)),
            )
        return (
            GateResult(
                gate=self.gate,
                status=GateStatus.PASS,
                reason=(
                    f"{len(findings)} finding(s) with {len(refs)} verified artifact(s), "
                    "complete provenance, and in-window timestamps"
                ),
                evidence_refs=tuple(sorted(refs)),
                checked_at=moment,
                checker_version=self.checker_version,
            ),
            tuple(sorted(refs)),
        )


class DeduplicationGate:
    gate = GateName.DEDUPLICATION
    checker_version = "dedup/1.0"
    similarity_threshold = 0.5

    def evaluate(
        self,
        *,
        engagement_id: str,
        target_id: str,
        bug_class: BugClass,
        findings: tuple[ToolFinding, ...],
        prior_findings: tuple[ValidatedFinding, ...],
        now: datetime,
    ) -> tuple[GateResult, DedupResult]:
        moment = ensure_utc(now)
        fingerprint = finding_fingerprint(
            engagement_id=engagement_id,
            target_id=target_id,
            bug_class_id=bug_class.bug_class_id,
            findings=findings,
        )
        tokens = evidence_tokens(findings)
        prior = tuple(
            finding
            for finding in prior_findings
            if finding.engagement_id == engagement_id
            and finding.dedup.status is not DuplicateStatus.DUPLICATE
        )

        for existing in prior:
            if existing.dedup.fingerprint == fingerprint:
                dedup = DedupResult(
                    status=DuplicateStatus.DUPLICATE,
                    fingerprint=fingerprint,
                    duplicate_of=existing.finding_id,
                    similarity=1.0,
                    reason="exact evidence fingerprint matches an existing validated finding",
                )
                return (
                    GateResult(
                        gate=self.gate,
                        status=GateStatus.FAIL,
                        reason=dedup.reason,
                        checked_at=moment,
                        checker_version=self.checker_version,
                    ),
                    dedup,
                )

        best: tuple[float, ValidatedFinding] | None = None
        for existing in prior:
            if existing.target_id != target_id or existing.bug_class_id != bug_class.bug_class_id:
                continue
            prior_tokens = {f"art:{ref}" for ref in existing.evidence_refs}
            score = similarity(tokens, prior_tokens)
            if best is None or score > best[0]:
                best = (score, existing)

        if best is not None and best[0] >= self.similarity_threshold:
            score, existing = best
            dedup = DedupResult(
                status=DuplicateStatus.POSSIBLE_DUPLICATE,
                fingerprint=fingerprint,
                duplicate_of=existing.finding_id,
                similarity=round(score, 6),
                reason=(
                    f"same target and bug class with {score:.0%} evidence-token overlap; "
                    "human deduplication review required"
                ),
            )
            return (
                GateResult(
                    gate=self.gate,
                    status=GateStatus.INCONCLUSIVE,
                    reason=dedup.reason,
                    checked_at=moment,
                    checker_version=self.checker_version,
                ),
                dedup,
            )

        dedup = DedupResult(
            status=DuplicateStatus.UNIQUE,
            fingerprint=fingerprint,
            similarity=0.0,
            reason="no exact or high-similarity prior finding for this target and bug class",
        )
        return (
            GateResult(
                gate=self.gate,
                status=GateStatus.PASS,
                reason=dedup.reason,
                checked_at=moment,
                checker_version=self.checker_version,
            ),
            dedup,
        )
