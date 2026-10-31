"""Shared builders for deterministic tests.

These helpers construct contracts directly; they do not exercise policy,
network, or persistence paths. Tests that need those use the fixtures in
``tests/conftest.py``.
"""

from __future__ import annotations

from datetime import timedelta
from urllib.parse import urlsplit

from huntress_contracts import (
    AssetConfidence,
    AssetKind,
    BugClass,
    DedupResult,
    DuplicateStatus,
    Engagement,
    EngagementMode,
    EngagementState,
    FindingConfidence,
    GateName,
    GateResult,
    GateStatus,
    HumanReviewStatus,
    KnowledgeSource,
    KnowledgeTier,
    KnowledgeUnit,
    OracleArchetype,
    ReproductionPolicyResult,
    ScanWorkstream,
    SeverityAssessment,
    SeverityBand,
    TargetRecord,
    ToolFinding,
    ValidatedFinding,
    ValidationStatus,
    get_bug_class,
    new_id,
    sha256_hex,
    utc_now,
)
from huntress_contracts.scope import AssetProvenance, ScopeAsset
from huntress_knowledge.hashing import make_knowledge_unit


def make_target(
    engagement_id: str,
    url: str,
    *,
    target_id: str | None = None,
    asset_id: str | None = None,
    in_scope: bool = True,
) -> TargetRecord:
    """Derive a target from a URL, mirroring deterministic target sync."""

    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("target URL must be absolute http(s)")
    scheme = parsed.scheme
    port = parsed.port or (443 if scheme == "https" else 80)
    now = utc_now()
    return TargetRecord(
        target_id=target_id or new_id("tgt"),
        engagement_id=engagement_id,
        asset_id=asset_id or "asset_" + sha256_hex(url)[:16],
        asset_kind=AssetKind.URL,
        host=parsed.hostname,
        scheme=scheme,
        port=port,
        base_url=url.rstrip("/"),
        source="pytest",
        confidence=AssetConfidence.CONFIRMED,
        first_seen=now,
        last_seen=now,
        in_scope=in_scope,
    )


def make_scope_asset(url: str, *, asset_id: str | None = None) -> ScopeAsset:
    return ScopeAsset(
        asset_id=asset_id or "asset_" + sha256_hex(url)[:16],
        kind=AssetKind.URL,
        value=url.rstrip("/"),
        provenance=AssetProvenance(
            source="pytest",
            observed_at=utc_now(),
            confidence=AssetConfidence.CONFIRMED,
        ),
    )


def make_engagement(
    *,
    engagement_id: str | None = None,
    state: EngagementState = EngagementState.READY,
    mode: EngagementMode = EngagementMode.LAB,
    scope_id: str = "scope_pytest000001",
    policy_version: str = "huntress-policy/1.0:scope-v1:0123456789abcdef",
) -> Engagement:
    now = utc_now()
    return Engagement(
        engagement_id=engagement_id or new_id("eng"),
        name="pytest engagement",
        mode=mode,
        state=state,
        program_id="pytest-lab",
        scope_id=scope_id,
        scope_version=1,
        policy_version=policy_version,
        created_at=now,
        updated_at=now,
        created_by="pytest",
    )


def make_tool_finding(
    *,
    engagement_id: str,
    target_id: str,
    bug_class_id: str = "bug_exposed_sensitive_file",
    finding_type: str = "http.env_exposure",
    artifact_refs: tuple[str, ...],
    details: dict[str, str | int | float | bool] | None = None,
    excerpt: str = "",
    profile_id: str = "http.exposed_files",
    observed_at=None,
    confidence: FindingConfidence = FindingConfidence.CONFIRMED_SIGNATURE,
) -> ToolFinding:
    bug_class: BugClass = get_bug_class(bug_class_id)
    return ToolFinding(
        finding_id=new_id("tf"),
        engagement_id=engagement_id,
        target_id=target_id,
        tool_profile_id=profile_id,
        tool_version="1.0.0",
        workstream=ScanWorkstream.SIGNATURE_CHECK,
        finding_type=finding_type,
        title=f"pytest observation for {bug_class_id}",
        bug_class_id=bug_class_id,
        cwe_ids=(bug_class.cwe_id,),
        confidence=confidence,
        oracle_hint=bug_class.oracle_archetype,
        artifact_refs=artifact_refs,
        observed_at=observed_at or utc_now(),
        excerpt=excerpt,
        details=dict(details or {}),
        evidence_fingerprint=sha256_hex("|".join(artifact_refs))[:128],
    )


def make_gate(
    gate: GateName,
    *,
    status: GateStatus = GateStatus.PASS,
    evidence_refs: tuple[str, ...] = (),
) -> GateResult:
    return GateResult(
        gate=gate,
        status=status,
        reason=f"pytest {gate.value} gate",
        evidence_refs=evidence_refs,
        checked_at=utc_now(),
        checker_version="pytest/1.0",
    )


def make_validated_finding(
    *,
    engagement_id: str,
    target_id: str,
    evidence_refs: tuple[str, ...],
    bug_class_id: str = "bug_exposed_sensitive_file",
    title: str = "Publicly exposed dotenv configuration",
    claim: str = "The approved target served a dotenv file with a credential assignment.",
    status: ValidationStatus = ValidationStatus.PASSED,
    human_review_status: HumanReviewStatus = HumanReviewStatus.APPROVED,
    reviewer: str | None = "Reviewer One",
    severity_band: SeverityBand = SeverityBand.HIGH,
    fingerprint: str | None = None,
    finding_id: str | None = None,
) -> ValidatedFinding:
    bug_class = get_bug_class(bug_class_id)
    gates = tuple(
        make_gate(gate, evidence_refs=evidence_refs)
        for gate in (
            GateName.SCOPE_RECHECK,
            GateName.EVIDENCE_COMPLETENESS,
            GateName.REPRODUCIBILITY,
            GateName.TECHNICAL_ORACLE,
            GateName.SEVERITY,
            GateName.DEDUPLICATION,
        )
    )
    return ValidatedFinding(
        finding_id=finding_id or new_id("vf"),
        engagement_id=engagement_id,
        tool_finding_ids=(new_id("tf"),),
        target_id=target_id,
        bug_class_id=bug_class.bug_class_id,
        oracle_archetype=bug_class.oracle_archetype,
        title=title,
        claim=claim,
        evidence_refs=evidence_refs,
        gates=gates,
        reproduction=ReproductionPolicyResult(
            policy_id="huntress-reproduction/1.0",
            required_repetitions=1,
            performed_repetitions=1,
            status=GateStatus.PASS,
            reason="pytest reproduction passed",
            side_effect_class="read_only",
        ),
        severity=SeverityAssessment(
            band=severity_band,
            method="qualitative",
            impact_summary="A credential-shaped assignment was disclosed publicly.",
        ),
        dedup=DedupResult(
            status=DuplicateStatus.UNIQUE,
            fingerprint=fingerprint or sha256_hex(f"{engagement_id}:{target_id}:{bug_class_id}"),
            reason="pytest unique",
        ),
        status=status,
        validated_at=utc_now(),
        human_review_status=human_review_status,
        reviewer=reviewer if human_review_status is HumanReviewStatus.APPROVED else None,
        reviewed_at=utc_now() if human_review_status is HumanReviewStatus.APPROVED else None,
    )


def make_knowledge(
    *,
    unit_id: str | None = None,
    tenant_scope: str = "global",
    title: str = "Error-based SQL injection differential",
    summary: str = "A quote probe that reliably produces a database error can be verified.",
    tags: tuple[str, ...] = ("sqli", "differential"),
    cwe_ids: tuple[int, ...] = (89,),
    oracle_archetypes: tuple[OracleArchetype, ...] = (OracleArchetype.DIFFERENTIAL_STATISTICAL,),
    freshness_at=None,
    supersedes: str | None = None,
    body_ref: str | None = None,
) -> KnowledgeUnit:
    now = utc_now()
    return make_knowledge_unit(
        unit_id=unit_id or new_id("ku"),
        tenant_scope=tenant_scope,
        tier=KnowledgeTier.TECHNIQUE,
        title=title,
        summary=summary,
        source=KnowledgeSource(
            uri="https://example.test/knowledge/sqli",
            publisher="pytest",
            fetched_at=now,
            content_hash=sha256_hex(summary),
            license="CC0",
            trust_tier="reviewed",
        ),
        freshness_at=freshness_at or now,
        created_at=now,
        tags=tags,
        cwe_ids=cwe_ids,
        oracle_archetypes=oracle_archetypes,
        supersedes=supersedes,
        body_ref=body_ref,
    )


def future_window(hours: int = 2):
    from huntress_contracts import TestingWindow

    now = utc_now()
    return TestingWindow(starts_at=now - timedelta(minutes=1), ends_at=now + timedelta(hours=hours))
