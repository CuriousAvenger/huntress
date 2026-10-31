"""Closed enums shared by every Huntress package.

Enums in this module are public contract surface. Adding a value is a minor
version change; renaming or removing one is a major version change.
"""

from __future__ import annotations

from enum import StrEnum


class EngagementMode(StrEnum):
    """Authorization context. Modes never inherit scope or credentials."""

    LAB = "lab"
    BOUNTY = "bounty"
    SHADOW = "shadow"


class EngagementState(StrEnum):
    """Durable lifecycle states from the architecture document."""

    CREATED = "CREATED"
    SCOPE_PENDING = "SCOPE_PENDING"
    READY = "READY"
    RECON = "RECON"
    ANALYSIS = "ANALYSIS"
    ACTION_PENDING = "ACTION_PENDING"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    EXECUTING = "EXECUTING"
    VALIDATING = "VALIDATING"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    REPORT_DRAFT = "REPORT_DRAFT"
    SUBMISSION_PENDING = "SUBMISSION_PENDING"
    CLOSED = "CLOSED"
    BLOCKED = "BLOCKED"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


class AssetKind(StrEnum):
    """How a scope asset is matched. Matching is deterministic and exact."""

    DOMAIN = "domain"
    WILDCARD_DOMAIN = "wildcard_domain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR = "cidr"
    URL = "url"
    REPOSITORY = "repository"
    ARTIFACT = "artifact"


class ScopeStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REVOKED = "revoked"


class AssetConfidence(StrEnum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    CANDIDATE = "candidate"


class HttpMethod(StrEnum):
    GET = "GET"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class RiskClass(StrEnum):
    """Ordered from least to most intrusive."""

    PASSIVE = "passive"
    LOW = "low"
    ACTIVE = "active"
    HIGH = "high"
    EXPLOIT_LIKE = "exploit_like"


_RISK_ORDER: dict[RiskClass, int] = {
    RiskClass.PASSIVE: 0,
    RiskClass.LOW: 1,
    RiskClass.ACTIVE: 2,
    RiskClass.HIGH: 3,
    RiskClass.EXPLOIT_LIKE: 4,
}


def risk_rank(value: RiskClass) -> int:
    return _RISK_ORDER[value]


class SideEffectClass(StrEnum):
    """Ordered from none to destructive. Used by reproduction policy."""

    NONE = "none"
    READ_ONLY = "read_only"
    REVERSIBLE = "reversible"
    MATERIAL = "material"
    DESTRUCTIVE = "destructive"


_SIDE_EFFECT_ORDER: dict[SideEffectClass, int] = {
    SideEffectClass.NONE: 0,
    SideEffectClass.READ_ONLY: 1,
    SideEffectClass.REVERSIBLE: 2,
    SideEffectClass.MATERIAL: 3,
    SideEffectClass.DESTRUCTIVE: 4,
}


def side_effect_rank(value: SideEffectClass) -> int:
    return _SIDE_EFFECT_ORDER[value]


class ProfileExecutor(StrEnum):
    """Where a reviewed profile runs. Builtins are in-process and deterministic."""

    BUILTIN = "builtin"
    EXEGOL = "exegol"


class ExecutionBackend(StrEnum):
    AUTO = "auto"
    EXEGOL = "exegol"
    FAKE = "fake"


class ActionKind(StrEnum):
    """Closed action vocabulary. The model cannot invent new actions."""

    INSPECT_INVENTORY = "inspect_inventory"
    RUN_APPROVED_PROFILE = "run_approved_profile"
    REVIEW_EVIDENCE = "review_evidence"
    REQUEST_HUMAN_REVIEW = "request_human_review"
    STOP = "stop"


class HypothesisStatus(StrEnum):
    PROPOSED = "proposed"
    TESTING = "testing"
    SUPPORTED = "supported"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"
    REJECTED = "rejected"


class ReasonCode(StrEnum):
    """Stable machine-readable policy reasons. Never parse prose."""

    ALLOWED = "allowed"
    DENIED_UNKNOWN_ENGAGEMENT = "denied_unknown_engagement"
    DENIED_ENGAGEMENT_STATE = "denied_engagement_state"
    DENIED_SCOPE_MISSING = "denied_scope_missing"
    DENIED_SCOPE_NOT_APPROVED = "denied_scope_not_approved"
    DENIED_SCOPE_EXPIRED = "denied_scope_expired"
    DENIED_SCOPE_INTEGRITY = "denied_scope_integrity"
    DENIED_TARGET_NOT_FOUND = "denied_target_not_found"
    DENIED_TARGET_OUT_OF_SCOPE = "denied_target_out_of_scope"
    DENIED_TARGET_EXCLUDED = "denied_target_excluded"
    DENIED_METHOD_NOT_ALLOWED = "denied_method_not_allowed"
    DENIED_PROFILE_UNKNOWN = "denied_profile_unknown"
    DENIED_PROFILE_NOT_ALLOWED = "denied_profile_not_allowed"
    DENIED_PROFILE_ASSET_KIND = "denied_profile_asset_kind"
    DENIED_RISK_NOT_ALLOWED = "denied_risk_not_allowed"
    DENIED_SIDE_EFFECT_NOT_ALLOWED = "denied_side_effect_not_allowed"
    DENIED_APPROVAL_REQUIRED = "denied_approval_required"
    DENIED_APPROVAL_INVALID = "denied_approval_invalid"
    DENIED_BUDGET_EXHAUSTED = "denied_budget_exhausted"
    DENIED_RATE_LIMITED = "denied_rate_limited"
    DENIED_IDEMPOTENT_REPLAY = "denied_idempotent_replay"
    DENIED_UNKNOWN_ACTION = "denied_unknown_action"
    DENIED_INVALID_REQUEST = "denied_invalid_request"
    DENIED_AVAILABILITY_DISABLED = "denied_availability_disabled"
    DENIED_EXPLOIT_NOT_AUTHORIZED = "denied_exploit_not_authorized"
    DENIED_REDIRECT_NOT_IN_SCOPE = "denied_redirect_not_in_scope"
    DENIED_CANCELLED = "denied_cancelled"


class LedgerStatus(StrEnum):
    RESERVED = "reserved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class BudgetReservationStatus(StrEnum):
    RESERVED = "reserved"
    COMMITTED = "committed"
    RELEASED = "released"


class OracleArchetype(StrEnum):
    """Fixed proof taxonomy. A vulnerability domain is not an oracle."""

    SIDE_EFFECT_EXECUTION = "side_effect_execution"
    OUT_OF_BAND = "out_of_band"
    DIFFERENTIAL_STATISTICAL = "differential_statistical"
    STATE_CHANGE_AUTHZ = "state_change_authz"
    CONTENT_MATCH = "content_match"
    CRASH_POV = "crash_pov"
    GRAPH_REACHABILITY = "graph_reachability"
    CRYPTOGRAPHIC_PROOF = "cryptographic_proof"
    COMPONENT_MATCH = "component_match"
    AVAILABILITY_BOUNDED = "availability_bounded"


class VulnerabilityDomain(StrEnum):
    WEB = "web"
    API = "api"
    CLOUD = "cloud"
    IDENTITY = "identity"
    NETWORK = "network"
    BINARY = "binary"
    MOBILE = "mobile"
    SOURCE_CODE = "source_code"


class FindingConfidence(StrEnum):
    """Deterministic triage class assigned by a parser, never by a model."""

    CONFIRMED_SIGNATURE = "confirmed_signature"
    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"
    INFORMATIONAL = "informational"


class ToolRunStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"
    SKIPPED = "skipped"


class ValidationStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"


class GateName(StrEnum):
    SCOPE_RECHECK = "scope_recheck"
    EVIDENCE_COMPLETENESS = "evidence_completeness"
    REPRODUCIBILITY = "reproducibility"
    TECHNICAL_ORACLE = "technical_oracle"
    SEVERITY = "severity"
    DEDUPLICATION = "deduplication"
    HUMAN_REVIEW = "human_review"


class GateStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"
    SKIPPED = "skipped"


class SeverityBand(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class DuplicateStatus(StrEnum):
    UNIQUE = "unique"
    POSSIBLE_DUPLICATE = "possible_duplicate"
    DUPLICATE = "duplicate"


class HumanReviewStatus(StrEnum):
    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    NEEDS_MORE_EVIDENCE = "needs_more_evidence"


class ReportStatus(StrEnum):
    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    SUBMITTED = "submitted"
    WITHDRAWN = "withdrawn"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    REVOKED = "revoked"


class ActorType(StrEnum):
    OPERATOR = "operator"
    SYSTEM = "system"
    AGENT = "agent"
    VALIDATOR = "validator"
    EXECUTOR = "executor"


class RedactionStatus(StrEnum):
    RAW = "raw"
    REDACTED = "redacted"
    SANITIZED = "sanitized"


class KnowledgeTier(StrEnum):
    TECHNIQUE = "technique"
    VERIFICATION = "verification"
    PROGRAM_POLICY = "program_policy"
    EPISODIC = "episodic"
    LAB = "lab"


class ContextTask(StrEnum):
    """The four deliberate reasoning checkpoints plus action selection."""

    ACTION_SELECTION = "action_selection"
    HYPOTHESIS_SYNTHESIS = "hypothesis_synthesis"
    FAILURE_REFLECTION = "failure_reflection"
    IMPACT_NARRATIVE = "impact_narrative"
    CROSS_ENGAGEMENT_REVIEW = "cross_engagement_review"


class ModelCallStatus(StrEnum):
    SUCCEEDED = "succeeded"
    INVALID_OUTPUT = "invalid_output"
    BUDGET_EXCEEDED = "budget_exceeded"
    CANCELLED = "cancelled"
    PROVIDER_ERROR = "provider_error"
    DISABLED = "disabled"


class DecisionSource(StrEnum):
    MODEL = "model"
    RULE_ENGINE = "rule_engine"
    OPERATOR = "operator"


class ScanWorkstream(StrEnum):
    PASSIVE_OSINT = "passive_osint"
    ACTIVE_ENUMERATION = "active_enumeration"
    WEB_SURFACE = "web_surface"
    SIGNATURE_CHECK = "signature_check"
    CVE_CORRELATION = "cve_correlation"
    DETECT_ONLY = "detect_only"
    CLIENT_ARTIFACT = "client_artifact"
    BINARY_IDENTITY = "binary_identity"
