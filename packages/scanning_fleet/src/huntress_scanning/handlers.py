"""Reviewed builtin handlers for HTTP and DNS discovery.

Handlers only use fixed paths, fixed parameter names, and a target resolved from
the approved inventory. Each HTTP request is individually authorized through
``ScanContext.authorize_url`` immediately before it is sent.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

import dns.exception
import dns.resolver
from huntress_contracts import (
    ArtifactProvenance,
    Engagement,
    HttpMethod,
    ScopeDocument,
    TargetRecord,
    ToolProfile,
    sha256_hex,
)
from huntress_evidence import ArtifactStore, artifact_provenance

from .http import BoundedHttpClient, safe_join, safe_query
from .models import HttpResponse, ScanObservation, ScanRequestError, ScanTimeout
from .parsers import (
    baseline_spec,
    cors_spec,
    dns_spec,
    exposed_file_spec,
    open_redirect_spec,
    reflection_spec,
    security_headers_spec,
    sqli_spec,
)

CANARY_ORIGIN = "https://huntress-canary.invalid"
CANARY_HOST = "huntress-canary.invalid"
CANARY_URL = "https://huntress-canary.invalid/huntress-open-redirect"

EXPOSED_PATHS: tuple[str, ...] = (
    "/.env",
    "/.git/HEAD",
    "/server-status",
    "/actuator/env",
    "/backup.zip",
    "/.DS_Store",
    "/phpinfo.php",
    "/uploads/",
)
REDIRECT_PARAMETERS: tuple[str, ...] = ("next", "url", "redirect", "return", "continue")
REFLECTION_PARAMETERS: tuple[str, ...] = ("q", "search")
SQLI_PARAMETER = "q"


class DnsResolver(Protocol):
    def __call__(self, host: str, record_type: str) -> tuple[str, ...]: ...


@dataclass
class ScanContext:
    engagement: Engagement
    target: TargetRecord
    scope: ScopeDocument
    profile: ToolProfile
    store: ArtifactStore
    http: BoundedHttpClient
    authorize_url: Callable[[str, HttpMethod], bool]
    action_request_id: str
    policy_version: str
    scope_hash: str
    now: datetime
    dns_resolver: DnsResolver
    request_count: int = 0
    truncated: bool = False
    artifact_refs: list[str] = field(default_factory=list)

    def record_request(self) -> None:
        self.request_count += 1


def _provenance(
    ctx: ScanContext,
    *,
    source_tool: str,
    exit_status: int | None,
    note: str = "",
) -> ArtifactProvenance:
    return artifact_provenance(
        source_tool=source_tool,
        tool_version=ctx.profile.version,
        engagement_id=ctx.engagement.engagement_id,
        target_id=ctx.target.target_id,
        asset_id=ctx.target.asset_id,
        profile_id=ctx.profile.profile_id,
        action_request_id=ctx.action_request_id,
        policy_version=ctx.policy_version,
        scope_hash=ctx.scope_hash,
        exit_status=exit_status,
        note=note,
        now=ctx.now,
    )


def _store_bytes(
    ctx: ScanContext,
    data: bytes,
    *,
    media_type: str,
    note: str,
    exit_status: int | None,
) -> str:
    ref = ctx.store.put(
        data,
        media_type=media_type,
        provenance=_provenance(ctx, source_tool=ctx.profile.profile_id, exit_status=exit_status, note=note),
    )
    ctx.artifact_refs.append(ref.sha256)
    return ref.sha256


def _store_json(ctx: ScanContext, value: Mapping[str, object], *, note: str) -> str:
    return _store_bytes(
        ctx,
        json.dumps(value, indent=2, sort_keys=True).encode("utf-8"),
        media_type="application/json",
        note=note,
        exit_status=None,
    )


def _capture_response(ctx: ScanContext, response: HttpResponse) -> tuple[str, str]:
    body_ref = _store_bytes(
        ctx,
        response.body,
        media_type=response.media_type,
        note=f"raw response body for {response.method.value} {response.url}",
        exit_status=response.status_code,
    )
    meta_ref = _store_json(
        ctx,
        {
            "url": response.url,
            "method": response.method.value,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "request_headers": dict(response.request_headers),
            "elapsed_ms": response.elapsed_ms,
            "truncated": response.truncated,
            "body_ref": body_ref,
        },
        note=f"response metadata for {response.method.value} {response.url}",
    )
    if response.truncated:
        ctx.truncated = True
    return body_ref, meta_ref


def _get(ctx: ScanContext, url: str, *, headers: Mapping[str, str] | None = None) -> HttpResponse:
    ctx.record_request()
    return ctx.http.get(url, headers=headers, authorize=ctx.authorize_url)


def handle_http_baseline(ctx: ScanContext) -> ScanObservation:
    response = _get(ctx, ctx.target.base_url)
    refs = _capture_response(ctx, response)
    spec = baseline_spec(response, refs)
    return ScanObservation(
        findings=(spec,),
        artifact_refs=tuple(ctx.artifact_refs),
        request_count=ctx.request_count,
        output_truncated=ctx.truncated,
        observed_at=ctx.now,
    )


def handle_http_security_headers(ctx: ScanContext) -> ScanObservation:
    response = _get(ctx, ctx.target.base_url)
    refs = _capture_response(ctx, response)
    spec = security_headers_spec(response, refs)
    return ScanObservation(
        findings=(spec,) if spec else (),
        artifact_refs=tuple(ctx.artifact_refs),
        request_count=ctx.request_count,
        output_truncated=ctx.truncated,
        observed_at=ctx.now,
    )


def handle_http_exposed_files(ctx: ScanContext) -> ScanObservation:
    specs = []
    for path in EXPOSED_PATHS:
        url = safe_join(ctx.target.base_url, path)
        try:
            response = _get(ctx, url)
        except (ScanRequestError, ScanTimeout):
            # A single unreachable path must not hide hits on the remaining paths.
            continue
        refs = _capture_response(ctx, response)
        spec = exposed_file_spec(response, path=path, artifact_refs=refs)
        if spec is not None:
            specs.append(spec)
    return ScanObservation(
        findings=tuple(specs),
        artifact_refs=tuple(ctx.artifact_refs),
        request_count=ctx.request_count,
        output_truncated=ctx.truncated,
        observed_at=ctx.now,
    )


def handle_http_cors(ctx: ScanContext) -> ScanObservation:
    response = _get(ctx, ctx.target.base_url, headers={"Origin": CANARY_ORIGIN})
    refs = _capture_response(ctx, response)
    spec = cors_spec(response, canary_origin=CANARY_ORIGIN, artifact_refs=refs)
    return ScanObservation(
        findings=(spec,) if spec else (),
        artifact_refs=tuple(ctx.artifact_refs),
        request_count=ctx.request_count,
        output_truncated=ctx.truncated,
        observed_at=ctx.now,
    )


def handle_http_open_redirect(ctx: ScanContext) -> ScanObservation:
    specs = []
    for parameter in REDIRECT_PARAMETERS:
        url = safe_query(ctx.target.base_url, {parameter: CANARY_URL})
        try:
            response = _get(ctx, url)
        except (ScanRequestError, ScanTimeout):
            continue
        refs = _capture_response(ctx, response)
        spec = open_redirect_spec(
            response,
            parameter=parameter,
            canary_host=CANARY_HOST,
            artifact_refs=refs,
        )
        if spec is not None:
            specs.append(spec)
            break
    return ScanObservation(
        findings=tuple(specs),
        artifact_refs=tuple(ctx.artifact_refs),
        request_count=ctx.request_count,
        output_truncated=ctx.truncated,
        observed_at=ctx.now,
    )


def handle_http_reflected_marker(ctx: ScanContext) -> ScanObservation:
    token = sha256_hex(f"{ctx.target.target_id}|{ctx.now.isoformat()}|{ctx.profile.profile_id}")[:16]
    marker = f'"><hx-canary data-token="{token}">'
    specs = []
    for parameter in REFLECTION_PARAMETERS:
        url = safe_query(ctx.target.base_url, {parameter: marker})
        try:
            response = _get(ctx, url)
        except (ScanRequestError, ScanTimeout):
            continue
        refs = _capture_response(ctx, response)
        spec = reflection_spec(response, marker=marker, artifact_refs=refs)
        if spec is not None:
            specs.append(spec)
            break
    return ScanObservation(
        findings=tuple(specs),
        artifact_refs=tuple(ctx.artifact_refs),
        request_count=ctx.request_count,
        output_truncated=ctx.truncated,
        observed_at=ctx.now,
    )


def handle_http_error_based_sqli(ctx: ScanContext) -> ScanObservation:
    baseline = _get(ctx, ctx.target.base_url)
    baseline_refs = _capture_response(ctx, baseline)
    probe_refs: list[str] = []
    probes: list[HttpResponse] = []
    payload = "'"
    for _ in range(3):
        url = safe_query(ctx.target.base_url, {SQLI_PARAMETER: payload})
        try:
            probe = _get(ctx, url)
        except (ScanRequestError, ScanTimeout):
            continue
        probes.append(probe)
        body_ref, _meta = _capture_response(ctx, probe)
        probe_refs.append(body_ref)
    spec = sqli_spec(
        baseline=baseline,
        probes=probes,
        baseline_ref=baseline_refs[0],
        probe_refs=probe_refs,
        payload=payload,
    )
    return ScanObservation(
        findings=(spec,) if spec else (),
        artifact_refs=tuple(ctx.artifact_refs),
        request_count=ctx.request_count,
        output_truncated=ctx.truncated,
        observed_at=ctx.now,
    )


def _system_dns_resolver(host: str, record_type: str) -> tuple[str, ...]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    resolver.timeout = 5.0
    try:
        answers = resolver.resolve(host, record_type, raise_on_no_answer=False)
    except dns.resolver.NXDOMAIN:
        return ()
    except dns.exception.Timeout as exc:
        raise ScanTimeout(f"DNS resolution timed out for {host}/{record_type}") from exc
    except dns.exception.DNSException as exc:
        raise ScanRequestError(f"DNS resolution failed for {host}/{record_type}: {exc}") from exc
    if answers.rrset is None:
        return ()
    values: list[str] = []
    for answer in answers:
        text = answer.to_text().rstrip(".")
        values.append(text)
    return tuple(sorted(set(values)))


def handle_dns_resolve(ctx: ScanContext) -> ScanObservation:
    host = ctx.target.host
    records: dict[str, tuple[str, ...]] = {}
    for record_type in ("A", "AAAA", "CNAME"):
        try:
            records[record_type] = ctx.dns_resolver(host, record_type)
        except (ScanRequestError, ScanTimeout):
            records[record_type] = ()
    artifact_ref = _store_json(
        ctx,
        {"host": host, "records": {key: list(value) for key, value in records.items()}},
        note="DNS resolution result",
    )
    spec = dns_spec(host=host, records=records, artifact_refs=(artifact_ref,))
    return ScanObservation(
        findings=(spec,),
        artifact_refs=tuple(ctx.artifact_refs),
        request_count=1,
        output_truncated=False,
        observed_at=ctx.now,
    )


BUILTIN_HANDLERS: dict[str, Callable[[ScanContext], ScanObservation]] = {
    "http_baseline": handle_http_baseline,
    "http_security_headers": handle_http_security_headers,
    "http_exposed_files": handle_http_exposed_files,
    "http_cors": handle_http_cors,
    "http_open_redirect": handle_http_open_redirect,
    "http_reflected_marker": handle_http_reflected_marker,
    "http_error_based_sqli": handle_http_error_based_sqli,
    "dns_resolve": handle_dns_resolve,
}
