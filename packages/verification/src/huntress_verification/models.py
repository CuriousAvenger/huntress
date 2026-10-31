"""Service-level models and ports for the validation pipeline.

These are internal dataclasses rather than public contracts: they carry
deterministic inputs into the gate pipeline and the persisted outcome out of
it. Public records remain the frozen Pydantic contracts in
``huntress_contracts``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from huntress_contracts import (
    AuditEvent,
    BugClass,
    DedupResult,
    Engagement,
    GateResult,
    HttpMethod,
    HumanReviewRecord,
    ScopeDocument,
    SideEffectClass,
    TargetRecord,
    ToolFinding,
    ValidatedFinding,
    ValidationStatus,
)

from .oracles import OracleResult
from .reproduction import ReproductionEvidence, ReproductionOutcome
from .severity import SeverityInputs, SeverityOutcome

_MAX_FACTS = 40
_MAX_FACT_KEY = 80
_MAX_FACT_STRING = 4000


@dataclass(frozen=True, slots=True)
class ValidationRequest:
    """Everything the deterministic pipeline needs to evaluate one candidate.

    ``oracle_facts`` must come from reviewed parsers or the operator. The
    service never derives facts from model prose; the oracle only accepts
    evidence references that are already part of the candidate's artifacts.
    """

    engagement: Engagement
    scope: ScopeDocument
    target: TargetRecord
    bug_class: BugClass
    findings: tuple[ToolFinding, ...]
    title: str
    claim: str
    method: HttpMethod
    signing_key: bytes
    oracle_facts: Mapping[str, str | int | float | bool] = field(default_factory=dict)
    reproduction: ReproductionEvidence = field(
        default_factory=lambda: ReproductionEvidence(performed_repetitions=1)
    )
    severity: SeverityInputs | None = None
    side_effect: SideEffectClass = SideEffectClass.READ_ONLY
    hypothesis_id: str | None = None
    finding_id: str | None = None
    now: datetime | None = None

    def __post_init__(self) -> None:
        if not self.findings:
            raise ValueError("a validation request requires at least one tool finding")
        finding_ids = [finding.finding_id for finding in self.findings]
        if len(set(finding_ids)) != len(finding_ids):
            raise ValueError("tool finding identifiers must be unique")
        if not self.title.strip():
            raise ValueError("validation title must not be empty")
        if len(self.claim.strip()) < 10:
            raise ValueError("validation claim must be at least 10 characters")
        if len(self.oracle_facts) > _MAX_FACTS:
            raise ValueError(f"oracle facts may not exceed {_MAX_FACTS} keys")
        for key, value in self.oracle_facts.items():
            if not key or len(key) > _MAX_FACT_KEY:
                raise ValueError("oracle fact keys must be 1-80 characters")
            if isinstance(value, str) and len(value) > _MAX_FACT_STRING:
                raise ValueError(f"oracle fact {key!r} exceeds the string cap")
        if not self.signing_key:
            raise ValueError("a non-empty scope signing key is required")


@dataclass(frozen=True, slots=True)
class ValidationOutcome:
    """Persisted finding plus every deterministic decision that produced it."""

    status: ValidationStatus
    finding: ValidatedFinding
    gates: tuple[GateResult, ...]
    oracle: OracleResult
    reproduction: ReproductionOutcome
    severity: SeverityOutcome
    dedup: DedupResult


@dataclass(frozen=True, slots=True)
class ReviewOutcome:
    """Durable review record plus the finding state it produced."""

    review: HumanReviewRecord
    finding: ValidatedFinding


class ValidationStore(Protocol):
    """Persistence port implemented by ``ValidationRepository``."""

    def save(self, finding: ValidatedFinding) -> ValidatedFinding: ...

    def get(self, finding_id: str) -> ValidatedFinding | None: ...

    def list_by_engagement(self, engagement_id: str) -> list[ValidatedFinding]: ...


class ReviewStore(Protocol):
    """Persistence port implemented by ``ReviewRepository``."""

    def save(self, review: HumanReviewRecord) -> HumanReviewRecord: ...

    def list_for_finding(self, finding_id: str) -> list[HumanReviewRecord]: ...


class AuditSink(Protocol):
    """Append-only audit port implemented by ``AuditRepository``."""

    def append(self, event: AuditEvent) -> AuditEvent: ...
