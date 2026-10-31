"""Pure parsers for reviewed discovery profiles.

Parsers take captured responses or resolver output and return ``FindingSpec``
values. They do not perform network I/O, which makes every signature rule
replayable in unit tests. A parser hit is still an observation, never a
validated vulnerability.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from urllib.parse import urlsplit

from huntress_contracts import (
    FindingConfidence,
    OracleArchetype,
    sha256_hex,
)

from .models import FindingSpec, HttpResponse

_SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("strict-transport-security", "Strict-Transport-Security"),
    ("content-security-policy", "Content-Security-Policy"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("x-frame-options", "X-Frame-Options"),
    ("referrer-policy", "Referrer-Policy"),
    ("permissions-policy", "Permissions-Policy"),
)

_SQL_ERROR_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"SQL syntax.*MySQL", re.IGNORECASE),
    re.compile(r"Warning.*\Wmysqli?_", re.IGNORECASE),
    re.compile(r"ORA-\d{4,5}", re.IGNORECASE),
    re.compile(r"PostgreSQL.*ERROR", re.IGNORECASE),
    re.compile(r"SQLite/JDBCDriver", re.IGNORECASE),
    re.compile(r"Microsoft OLE DB Provider for SQL Server", re.IGNORECASE),
    re.compile(r"Unclosed quotation mark", re.IGNORECASE),
    re.compile(r"syntax error at or near", re.IGNORECASE),
    re.compile(r"quoted string not properly terminated", re.IGNORECASE),
)

_SECRET_ASSIGNMENT = re.compile(
    r"(?im)^\s*[A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|APP_KEY|PRIVATE_KEY|"
    r"DATABASE_URL|DB_PASSWORD)[A-Z0-9_]*\s*=\s*\S+"
)
def _fingerprint(*parts: object) -> str:
    return sha256_hex("|".join(str(part) for part in parts))


def _bounded_excerpt(text: str, *, limit: int = 600) -> str:
    cleaned = text.replace("\x00", "").strip()
    return cleaned[:limit]


def baseline_spec(response: HttpResponse, artifact_refs: Sequence[str]) -> FindingSpec:
    """Informational baseline used as control evidence by later checks."""

    server = response.header("server") or "unknown"
    content_type = response.header("content-type") or "unknown"
    return FindingSpec(
        finding_type="http.baseline",
        title=f"HTTP baseline: {response.status_code} from {urlsplit(response.url).hostname}",
        confidence=FindingConfidence.INFORMATIONAL,
        artifact_refs=tuple(artifact_refs),
        excerpt="",
        details={
            "status_code": response.status_code,
            "server": server[:200],
            "content_type": content_type[:200],
            "body_bytes": len(response.body),
            "truncated": response.truncated,
            "elapsed_ms": response.elapsed_ms,
        },
        evidence_fingerprint=_fingerprint("baseline", response.status_code, server, content_type),
    )


def security_headers_spec(response: HttpResponse, artifact_refs: Sequence[str]) -> FindingSpec | None:
    """Report missing hardening headers as informational configuration evidence."""

    missing = [display for header, display in _SECURITY_HEADERS if not response.header(header)]
    if not missing:
        return None
    return FindingSpec(
        finding_type="http.missing_security_headers",
        title=f"Missing HTTP security headers ({len(missing)})",
        confidence=FindingConfidence.INFORMATIONAL,
        artifact_refs=tuple(artifact_refs),
        bug_class_id="bug_security_misconfiguration",
        cwe_ids=(16,),
        oracle_hint=OracleArchetype.CONTENT_MATCH,
        details={
            "missing_headers": ",".join(missing),
            "status_code": response.status_code,
        },
        evidence_fingerprint=_fingerprint("headers", *missing),
    )


def directory_listing_spec(response: HttpResponse, artifact_refs: Sequence[str]) -> FindingSpec | None:
    """Detect a classic auto-generated directory index."""

    text = response.text[:200_000]
    if response.status_code != 200:
        return None
    if not re.search(r"<title>\s*Index of /", text, re.IGNORECASE):
        return None
    if "Parent Directory" not in text:
        return None
    return FindingSpec(
        finding_type="http.directory_listing",
        title="Directory listing is enabled",
        confidence=FindingConfidence.STRONG,
        artifact_refs=tuple(artifact_refs),
        bug_class_id="bug_directory_listing",
        cwe_ids=(548,),
        oracle_hint=OracleArchetype.CONTENT_MATCH,
        excerpt=_bounded_excerpt(text),
        details={"status_code": response.status_code, "path": urlsplit(response.url).path},
        evidence_fingerprint=_fingerprint("directory-listing", urlsplit(response.url).path),
    )


def exposed_file_spec(
    response: HttpResponse,
    *,
    path: str,
    artifact_refs: Sequence[str],
) -> FindingSpec | None:
    """Match a response against one fixed sensitive-file rule."""

    text = response.text
    status = response.status_code
    content_type = (response.header("content-type") or "").lower()
    bug_class_id: str | None = None
    finding_type = "http.exposed_file"
    title = f"Potentially exposed file: {path}"
    signature = ""
    confidence = FindingConfidence.MODERATE

    if path == "/.env" and status == 200 and _SECRET_ASSIGNMENT.search(text):
        bug_class_id = "bug_env_exposure"
        finding_type = "http.env_exposure"
        title = "Publicly exposed dotenv configuration"
        signature = "secret_assignment"
        confidence = FindingConfidence.CONFIRMED_SIGNATURE
    elif path == "/.git/HEAD" and status == 200 and (
        text.startswith("ref: refs/") or re.fullmatch(r"[0-9a-f]{40}\s*", text) is not None
    ):
        bug_class_id = "bug_git_exposure"
        finding_type = "http.git_exposure"
        title = "Exposed Git repository metadata"
        signature = "git_head"
        confidence = FindingConfidence.CONFIRMED_SIGNATURE
    elif path == "/server-status" and status == 200 and (
        "Apache Server Status" in text or ("Server Status" in text and "requests" in text)
    ):
        bug_class_id = "bug_exposed_sensitive_file"
        finding_type = "http.server_status"
        title = "Exposed web server status page"
        signature = "server_status"
        confidence = FindingConfidence.STRONG
    elif path == "/actuator/env" and status == 200 and (
        '"propertySources"' in text or '"activeProfiles"' in text or '"systemProperties"' in text
    ):
        bug_class_id = "bug_actuator_exposure"
        finding_type = "http.actuator_exposure"
        title = "Exposed Spring actuator environment"
        signature = "actuator_env"
        confidence = FindingConfidence.STRONG
    elif path == "/backup.zip" and status == 200 and (
        response.body.startswith(b"PK\x03\x04") or "zip" in content_type
    ):
        bug_class_id = "bug_exposed_sensitive_file"
        finding_type = "http.backup_exposure"
        title = "Downloadable backup archive"
        signature = "zip_archive"
        confidence = FindingConfidence.STRONG
    elif path == "/.DS_Store" and status == 200 and response.body.startswith(b"\x00\x00\x00\x01Bud1"):
        bug_class_id = "bug_exposed_sensitive_file"
        finding_type = "http.ds_store"
        title = "Exposed macOS .DS_Store metadata"
        signature = "ds_store"
        confidence = FindingConfidence.STRONG
    elif path == "/phpinfo.php" and status == 200 and "PHP Version" in text:
        bug_class_id = "bug_exposed_sensitive_file"
        finding_type = "http.phpinfo"
        title = "Exposed PHP configuration page"
        signature = "phpinfo"
        confidence = FindingConfidence.STRONG
    elif path == "/uploads/" and status == 200:
        return directory_listing_spec(response, artifact_refs)
    else:
        return None

    # Never retain a whole environment/actuator body in the model context.
    excerpt = "" if bug_class_id in {"bug_env_exposure", "bug_actuator_exposure"} else _bounded_excerpt(text)
    return FindingSpec(
        finding_type=finding_type,
        title=title,
        confidence=confidence,
        artifact_refs=tuple(artifact_refs),
        bug_class_id=bug_class_id,
        cwe_ids=(200,) if bug_class_id != "bug_git_exposure" else (527,),
        oracle_hint=OracleArchetype.CONTENT_MATCH,
        excerpt=excerpt,
        details={
            "path": path,
            "status_code": status,
            "content_type": content_type[:120],
            "signature": signature,
        },
        evidence_fingerprint=_fingerprint("exposed-file", path, signature, len(response.body)),
        signature_ref=signature,
    )


def cors_spec(
    response: HttpResponse,
    *,
    canary_origin: str,
    artifact_refs: Sequence[str],
) -> FindingSpec | None:
    allow_origin = response.header("access-control-allow-origin")
    allow_credentials = (response.header("access-control-allow-credentials") or "").lower()
    if not allow_origin or allow_credentials != "true":
        return None
    if allow_origin not in {canary_origin, "*"}:
        return None
    reflected = allow_origin == canary_origin
    return FindingSpec(
        finding_type="http.cors_credentials",
        title="CORS reflects an untrusted origin with credentials enabled",
        confidence=FindingConfidence.STRONG if reflected else FindingConfidence.MODERATE,
        artifact_refs=tuple(artifact_refs),
        bug_class_id="bug_cors_misconfiguration",
        cwe_ids=(942,),
        oracle_hint=OracleArchetype.CONTENT_MATCH,
        details={
            "allow_origin": allow_origin,
            "allow_credentials": allow_credentials,
            "canary_origin": canary_origin,
            "reflected": reflected,
        },
        evidence_fingerprint=_fingerprint("cors", allow_origin, allow_credentials),
    )


def open_redirect_spec(
    response: HttpResponse,
    *,
    parameter: str,
    canary_host: str,
    artifact_refs: Sequence[str],
) -> FindingSpec | None:
    if not 300 <= response.status_code < 400:
        return None
    location = response.header("location")
    if not location:
        return None
    host = (urlsplit(location).hostname or "").lower().rstrip(".")
    if host != canary_host.lower().rstrip("."):
        return None
    return FindingSpec(
        finding_type="http.open_redirect",
        title=f"Open redirect via parameter {parameter!r}",
        confidence=FindingConfidence.STRONG,
        artifact_refs=tuple(artifact_refs),
        bug_class_id="bug_open_redirect",
        cwe_ids=(601,),
        oracle_hint=OracleArchetype.CONTENT_MATCH,
        details={
            "parameter": parameter,
            "location": location[:1000],
            "status_code": response.status_code,
        },
        evidence_fingerprint=_fingerprint("open-redirect", parameter, host),
    )


def reflection_spec(
    response: HttpResponse,
    *,
    marker: str,
    artifact_refs: Sequence[str],
) -> FindingSpec | None:
    """Detect raw reflection of an inert HTML-injection marker.

    This is intentionally only a candidate. The verification oracle requires
    executable context and will normally return inconclusive for a reflection
    in plain text.
    """

    text = response.text
    index = text.find(marker)
    if index < 0:
        return None
    start = max(0, index - 120)
    end = min(len(text), index + len(marker) + 120)
    context = text[start:end]
    return FindingSpec(
        finding_type="http.reflected_html_marker",
        title="User-controlled marker reflected without HTML escaping",
        confidence=FindingConfidence.MODERATE,
        artifact_refs=tuple(artifact_refs),
        bug_class_id="bug_reflected_xss",
        cwe_ids=(79,),
        oracle_hint=OracleArchetype.CONTENT_MATCH,
        excerpt=_bounded_excerpt(context),
        details={
            "marker": marker[:200],
            "context": "html_raw",
            "status_code": response.status_code,
        },
        evidence_fingerprint=_fingerprint("reflection", marker),
    )


def sql_error_match(text: str) -> str | None:
    """Return the literal database-error substring found in ``text``, if any.

    The differential oracle needs the actual matched text, not the regex
    pattern, so it can prove the same signal appears in every probe and is
    absent from the baseline.
    """

    for pattern in _SQL_ERROR_PATTERNS:
        match = pattern.search(text)
        if match is not None:
            return match.group(0)
    return None


def sqli_spec(
    *,
    baseline: HttpResponse,
    probes: Sequence[HttpResponse],
    baseline_ref: str,
    probe_refs: Sequence[str],
    payload: str,
) -> FindingSpec | None:
    """Match a database error present in every probe and absent from baseline."""

    if not probes:
        return None
    baseline_text = baseline.text
    matched: str | None = None
    for response in probes:
        probe_match: str | None = None
        for pattern in _SQL_ERROR_PATTERNS:
            if pattern.search(response.text) and not pattern.search(baseline_text):
                probe_match = pattern.pattern
                break
        if probe_match is None:
            return None
        matched = probe_match
    if matched is None:
        return None
    refs = (baseline_ref, *probe_refs)
    return FindingSpec(
        finding_type="http.error_based_sqli",
        title="Database error signature triggered by a bounded quote probe",
        confidence=FindingConfidence.STRONG,
        artifact_refs=refs,
        bug_class_id="bug_error_based_sqli",
        cwe_ids=(89,),
        oracle_hint=OracleArchetype.DIFFERENTIAL_STATISTICAL,
        excerpt="",
        details={
            "signature": matched[:200],
            "baseline_artifact_ref": baseline_ref,
            "probe_artifact_refs": ",".join(probe_refs),
            "repetitions": len(probes),
            "payload": payload,
        },
        evidence_fingerprint=_fingerprint("sqli", matched, *probe_refs),
    )


def dns_spec(
    *,
    host: str,
    records: Mapping[str, Iterable[str]],
    artifact_refs: Sequence[str],
) -> FindingSpec:
    normalized = {name: tuple(sorted(set(values))) for name, values in records.items()}
    count = sum(len(values) for values in normalized.values())
    return FindingSpec(
        finding_type="dns.records",
        title=f"DNS records for {host}",
        confidence=FindingConfidence.INFORMATIONAL,
        artifact_refs=tuple(artifact_refs),
        excerpt=json.dumps(normalized, sort_keys=True)[:1000],
        details={
            "a_count": len(normalized.get("A", ())),
            "aaaa_count": len(normalized.get("AAAA", ())),
            "cname_count": len(normalized.get("CNAME", ())),
            "record_count": count,
        },
        evidence_fingerprint=_fingerprint("dns", host, json.dumps(normalized, sort_keys=True)),
    )
