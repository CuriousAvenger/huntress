"""Deterministic validation gates, proof oracles, severity, and deduplication."""

from .cvss import CvssScore, parse_vector, score_vector
from .errors import ReviewDenied, ValidationConflict, VerificationError
from .fingerprints import evidence_tokens, finding_fingerprint, similarity
from .gates import DeduplicationGate, EvidenceGate, ScopeGate
from .human_review import HumanReviewService
from .models import (
    AuditSink,
    ReviewOutcome,
    ReviewStore,
    ValidationOutcome,
    ValidationRequest,
    ValidationStore,
)
from .oracles import (
    DEFAULT_ORACLE_REGISTRY,
    AvailabilityBoundedOracle,
    ComponentMatchOracle,
    ContentMatchOracle,
    CrashPoVOracle,
    CryptographicProofOracle,
    DifferentialStatisticalOracle,
    GraphReachabilityOracle,
    Oracle,
    OracleRegistry,
    OracleRequest,
    OracleResult,
    OutOfBandOracle,
    SideEffectExecutionOracle,
    StateChangeAuthzOracle,
)
from .reproduction import (
    DEFAULT_REPRODUCTION_POLICY,
    ReproductionEvidence,
    ReproductionOutcome,
    ReproductionPolicy,
)
from .service import ValidationService
from .severity import SeverityAssessor, SeverityInputs, SeverityOutcome, band_for_score

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_ORACLE_REGISTRY",
    "DEFAULT_REPRODUCTION_POLICY",
    "AuditSink",
    "AvailabilityBoundedOracle",
    "ComponentMatchOracle",
    "ContentMatchOracle",
    "CrashPoVOracle",
    "CryptographicProofOracle",
    "CvssScore",
    "DeduplicationGate",
    "DifferentialStatisticalOracle",
    "EvidenceGate",
    "GraphReachabilityOracle",
    "HumanReviewService",
    "Oracle",
    "OracleRegistry",
    "OracleRequest",
    "OracleResult",
    "OutOfBandOracle",
    "ReproductionEvidence",
    "ReproductionOutcome",
    "ReproductionPolicy",
    "ReviewDenied",
    "ReviewOutcome",
    "ReviewStore",
    "ScopeGate",
    "SeverityAssessor",
    "SeverityInputs",
    "SeverityOutcome",
    "SideEffectExecutionOracle",
    "StateChangeAuthzOracle",
    "ValidationConflict",
    "ValidationOutcome",
    "ValidationRequest",
    "ValidationService",
    "ValidationStore",
    "VerificationError",
    "band_for_score",
    "evidence_tokens",
    "finding_fingerprint",
    "parse_vector",
    "score_vector",
    "similarity",
]
