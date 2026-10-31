"""Replayable parser rules for reviewed discovery profiles."""

from __future__ import annotations

from huntress_contracts import FindingConfidence, HttpMethod, OracleArchetype, sha256_hex
from huntress_scanning import (
    baseline_spec,
    cors_spec,
    directory_listing_spec,
    dns_spec,
    exposed_file_spec,
    open_redirect_spec,
    reflection_spec,
    security_headers_spec,
    sqli_spec,
)
from huntress_scanning.models import HttpResponse
from huntress_scanning.parsers import sql_error_match

REF = sha256_hex("body")


def response(
    *,
    url: str = "http://127.0.0.1:8080/",
    status: int = 200,
    headers: tuple[tuple[str, str], ...] = (),
    body: bytes = b"",
    method: HttpMethod = HttpMethod.GET,
) -> HttpResponse:
    return HttpResponse(
        url=url,
        method=method,
        status_code=status,
        headers=headers,
        body=body,
        elapsed_ms=1,
    )


def test_env_exposure_requires_secret_assignment_and_hides_body() -> None:
    hit = exposed_file_spec(
        response(body=b"DEBUG=true\nDATABASE_PASSWORD=supersecret\n"),
        path="/.env",
        artifact_refs=(REF,),
    )
    assert hit is not None
    assert hit.bug_class_id == "bug_env_exposure"
    assert hit.confidence is FindingConfidence.CONFIRMED_SIGNATURE
    assert hit.excerpt == ""
    assert hit.details["signature"] == "secret_assignment"

    miss = exposed_file_spec(
        response(body=b"DEBUG=true\nAPP_NAME=lab\n"),
        path="/.env",
        artifact_refs=(REF,),
    )
    assert miss is None


def test_git_head_detection() -> None:
    hit = exposed_file_spec(
        response(body=b"ref: refs/heads/main\n"),
        path="/.git/HEAD",
        artifact_refs=(REF,),
    )
    assert hit is not None
    assert hit.bug_class_id == "bug_git_exposure"
    assert hit.cwe_ids == (527,)


def test_directory_listing_requires_index_and_parent_link() -> None:
    body = b"<html><title>Index of /uploads</title><a href='../'>Parent Directory</a></html>"
    hit = directory_listing_spec(response(body=body), (REF,))
    assert hit is not None
    assert hit.bug_class_id == "bug_directory_listing"

    miss = directory_listing_spec(response(body=b"<html>hello</html>"), (REF,))
    assert miss is None


def test_uploads_path_delegates_to_directory_listing() -> None:
    body = b"<html><title>Index of /uploads/</title><a href='../'>Parent Directory</a></html>"
    hit = exposed_file_spec(response(body=body), path="/uploads/", artifact_refs=(REF,))
    assert hit is not None
    assert hit.finding_type == "http.directory_listing"


def test_cors_requires_reflected_origin_with_credentials() -> None:
    canary = "https://huntress-canary.invalid"
    hit = cors_spec(
        response(
            headers=(
                ("Access-Control-Allow-Origin", canary),
                ("Access-Control-Allow-Credentials", "true"),
            )
        ),
        canary_origin=canary,
        artifact_refs=(REF,),
    )
    assert hit is not None
    assert hit.details["reflected"] is True
    assert hit.bug_class_id == "bug_cors_misconfiguration"

    wildcard = cors_spec(
        response(
            headers=(
                ("Access-Control-Allow-Origin", "*"),
                ("Access-Control-Allow-Credentials", "true"),
            )
        ),
        canary_origin=canary,
        artifact_refs=(REF,),
    )
    assert wildcard is not None
    assert wildcard.confidence is FindingConfidence.MODERATE

    no_credentials = cors_spec(
        response(headers=(("Access-Control-Allow-Origin", canary),)),
        canary_origin=canary,
        artifact_refs=(REF,),
    )
    assert no_credentials is None


def test_open_redirect_matches_only_the_canary_host() -> None:
    canary = "huntress-canary.invalid"
    hit = open_redirect_spec(
        response(status=302, headers=(("Location", f"https://{canary}/next"),)),
        parameter="next",
        canary_host=canary,
        artifact_refs=(REF,),
    )
    assert hit is not None
    assert hit.bug_class_id == "bug_open_redirect"
    assert hit.details["parameter"] == "next"

    miss = open_redirect_spec(
        response(status=302, headers=(("Location", "https://example.com/next"),)),
        parameter="next",
        canary_host=canary,
        artifact_refs=(REF,),
    )
    assert miss is None
    not_redirect = open_redirect_spec(
        response(status=200, headers=(("Location", f"https://{canary}/next"),)),
        parameter="next",
        canary_host=canary,
        artifact_refs=(REF,),
    )
    assert not_redirect is None


def test_reflection_returns_bounded_context() -> None:
    marker = '"><hx-canary data-token="abc">'
    body = f"<html><body><div>{marker}</div></body></html>".encode()
    hit = reflection_spec(response(body=body), marker=marker, artifact_refs=(REF,))
    assert hit is not None
    assert hit.bug_class_id == "bug_reflected_xss"
    assert marker in hit.excerpt
    assert hit.oracle_hint is OracleArchetype.CONTENT_MATCH


def test_sql_error_match_returns_the_literal_match() -> None:
    text = "<pre>SQL syntax error near 'x' in MySQL</pre>"
    matched = sql_error_match(text)
    assert matched is not None
    assert "SQL syntax" in matched
    assert sql_error_match("all good") is None


def test_sqli_spec_requires_error_in_every_probe_and_absent_baseline() -> None:
    baseline = response(body=b"<html>ok</html>")
    error_body = b"<html><pre>SQL syntax error in MySQL near '''</pre></html>"
    probes = [response(body=error_body), response(body=error_body), response(body=error_body)]
    spec = sqli_spec(
        baseline=baseline,
        probes=probes,
        baseline_ref="a" * 64,
        probe_refs=["b" * 64, "c" * 64, "d" * 64],
        payload="'",
    )
    assert spec is not None
    assert spec.bug_class_id == "bug_error_based_sqli"
    assert spec.oracle_hint is OracleArchetype.DIFFERENTIAL_STATISTICAL
    assert spec.details["repetitions"] == 3
    assert "SQL syntax" in str(spec.details["signature"])

    mixed = sqli_spec(
        baseline=baseline,
        probes=[probes[0], response(body=b"ok")],
        baseline_ref="a" * 64,
        probe_refs=["b" * 64, "c" * 64],
        payload="'",
    )
    assert mixed is None

    baseline_has_error = sqli_spec(
        baseline=response(body=error_body),
        probes=probes,
        baseline_ref="a" * 64,
        probe_refs=["b" * 64, "c" * 64, "d" * 64],
        payload="'",
    )
    assert baseline_has_error is None


def test_security_headers_reports_only_missing_headers() -> None:
    spec = security_headers_spec(
        response(headers=(("Content-Security-Policy", "default-src 'self'"),)),
        (REF,),
    )
    assert spec is not None
    assert "Strict-Transport-Security" in str(spec.details["missing_headers"])
    assert "Content-Security-Policy" not in str(spec.details["missing_headers"])


def test_baseline_and_dns_specs_are_deterministic() -> None:
    baseline = baseline_spec(
        response(headers=(("Server", "pytest"), ("Content-Type", "text/html")), body=b"hello"),
        (REF,),
    )
    assert baseline.confidence is FindingConfidence.INFORMATIONAL
    assert baseline.details["body_bytes"] == 5
    assert baseline.evidence_fingerprint == baseline_spec(
        response(headers=(("Server", "pytest"), ("Content-Type", "text/html")), body=b"hello"),
        (REF,),
    ).evidence_fingerprint

    dns = dns_spec(
        host="lab.test",
        records={"A": ("127.0.0.1",), "AAAA": ("::1",), "CNAME": ()},
        artifact_refs=(REF,),
    )
    assert dns.details["record_count"] == 2
    assert dns.details["a_count"] == 1
