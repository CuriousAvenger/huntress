"""Canonical bug-class vocabulary and oracle mapping.

Keep this small and stable. A bug class says *what* the weakness is; the oracle
says *what evidence pattern* can prove it. Adding entries is a reviewed change.
"""

from __future__ import annotations

from .enums import OracleArchetype, VulnerabilityDomain
from .findings import BugClass

BUG_CLASSES: dict[str, BugClass] = {
    "bug_exposed_sensitive_file": BugClass(
        bug_class_id="bug_exposed_sensitive_file",
        cwe_id=200,
        name="Exposure of Sensitive Information to an Unauthorized Actor",
        domain=VulnerabilityDomain.WEB,
        oracle_archetype=OracleArchetype.CONTENT_MATCH,
        description=(
            "A publicly reachable response exposes data that should require authorization, "
            "such as environment files, backups, or internal status pages."
        ),
        default_severity_hint="medium",
        tags=("web", "exposure", "content"),
    ),
    "bug_git_exposure": BugClass(
        bug_class_id="bug_git_exposure",
        cwe_id=527,
        name="Exposure of Version-Control Repository",
        domain=VulnerabilityDomain.WEB,
        oracle_archetype=OracleArchetype.CONTENT_MATCH,
        description=(
            "A version-control metadata endpoint is reachable and returns a valid repository "
            "marker, allowing source reconstruction."
        ),
        default_severity_hint="high",
        tags=("web", "source-disclosure", "content"),
    ),
    "bug_env_exposure": BugClass(
        bug_class_id="bug_env_exposure",
        cwe_id=538,
        name="Exposure of Environment Configuration",
        domain=VulnerabilityDomain.WEB,
        oracle_archetype=OracleArchetype.CONTENT_MATCH,
        description=(
            "A dotenv-style configuration file is served publicly and contains at least one "
            "credential-shaped assignment."
        ),
        default_severity_hint="high",
        tags=("web", "secrets", "content"),
    ),
    "bug_directory_listing": BugClass(
        bug_class_id="bug_directory_listing",
        cwe_id=548,
        name="Exposure of Information Through Directory Listing",
        domain=VulnerabilityDomain.WEB,
        oracle_archetype=OracleArchetype.CONTENT_MATCH,
        description="An HTTP directory index is enabled and lists files to unauthenticated users.",
        default_severity_hint="low",
        tags=("web", "content"),
    ),
    "bug_actuator_exposure": BugClass(
        bug_class_id="bug_actuator_exposure",
        cwe_id=200,
        name="Exposed Management or Actuator Endpoint",
        domain=VulnerabilityDomain.WEB,
        oracle_archetype=OracleArchetype.CONTENT_MATCH,
        description=(
            "A framework management endpoint returns internal configuration or environment "
            "data without authentication."
        ),
        default_severity_hint="high",
        tags=("web", "exposure", "content"),
    ),
    "bug_cors_misconfiguration": BugClass(
        bug_class_id="bug_cors_misconfiguration",
        cwe_id=942,
        name="Permissive Cross-domain Policy with Untrusted Domains",
        domain=VulnerabilityDomain.WEB,
        oracle_archetype=OracleArchetype.CONTENT_MATCH,
        description=(
            "The response reflects an attacker-controlled Origin in Access-Control-Allow-Origin "
            "and permits credentials."
        ),
        default_severity_hint="medium",
        tags=("web", "cors", "content"),
    ),
    "bug_open_redirect": BugClass(
        bug_class_id="bug_open_redirect",
        cwe_id=601,
        name="URL Redirection to Untrusted Site",
        domain=VulnerabilityDomain.WEB,
        oracle_archetype=OracleArchetype.CONTENT_MATCH,
        description=(
            "A user-controlled parameter causes a redirect to a tester-controlled canary host, "
            "confirmed by the Location header."
        ),
        default_severity_hint="low",
        tags=("web", "redirect", "content"),
    ),
    "bug_reflected_xss": BugClass(
        bug_class_id="bug_reflected_xss",
        cwe_id=79,
        name="Improper Neutralization of Input During Web Page Generation",
        domain=VulnerabilityDomain.WEB,
        oracle_archetype=OracleArchetype.CONTENT_MATCH,
        description=(
            "A unique canary marker is reflected unescaped in an executable HTML context. "
            "The oracle checks exact surrounding context, not a substring alone."
        ),
        default_severity_hint="medium",
        tags=("web", "xss", "content"),
    ),
    "bug_error_based_sqli": BugClass(
        bug_class_id="bug_error_based_sqli",
        cwe_id=89,
        name="Improper Neutralization of Special Elements used in an SQL Command",
        domain=VulnerabilityDomain.WEB,
        oracle_archetype=OracleArchetype.DIFFERENTIAL_STATISTICAL,
        description=(
            "A bounded probe produces a database error signature that is absent in the "
            "baseline response and survives repeated trials."
        ),
        default_severity_hint="high",
        tags=("web", "sqli", "differential"),
    ),
    "bug_security_misconfiguration": BugClass(
        bug_class_id="bug_security_misconfiguration",
        cwe_id=16,
        name="Configuration",
        domain=VulnerabilityDomain.WEB,
        oracle_archetype=OracleArchetype.CONTENT_MATCH,
        description=(
            "A missing or weak security header is observed. This is an informational "
            "configuration observation unless impact is independently demonstrated."
        ),
        default_severity_hint="info",
        tags=("web", "configuration", "informational"),
    ),
    "bug_outdated_component": BugClass(
        bug_class_id="bug_outdated_component",
        cwe_id=1104,
        name="Use of Unmaintained Third Party Components",
        domain=VulnerabilityDomain.WEB,
        oracle_archetype=OracleArchetype.COMPONENT_MATCH,
        description=(
            "A component fingerprint matches an affected version range. A version match "
            "alone is not a confirmed vulnerability; reachability must be shown."
        ),
        default_severity_hint="unknown",
        tags=("web", "component", "version"),
    ),
    "bug_cleartext_transmission": BugClass(
        bug_class_id="bug_cleartext_transmission",
        cwe_id=319,
        name="Cleartext Transmission of Sensitive Information",
        domain=VulnerabilityDomain.NETWORK,
        oracle_archetype=OracleArchetype.DIFFERENTIAL_STATISTICAL,
        description=(
            "Sensitive data is demonstrably transmitted over plaintext HTTP. Requires a "
            "bounded, non-destructive observation of the transport."
        ),
        default_severity_hint="medium",
        tags=("network", "tls", "differential"),
    ),
}

_BY_ID = BUG_CLASSES


def get_bug_class(bug_class_id: str) -> BugClass:
    """Return the canonical bug class or raise a clear error."""

    try:
        return _BY_ID[bug_class_id]
    except KeyError as exc:
        raise KeyError(f"unknown bug class: {bug_class_id}") from exc


def bug_class_ids() -> frozenset[str]:
    return frozenset(_BY_ID)
