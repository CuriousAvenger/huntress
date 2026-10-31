"""Reviewed builtin discovery profiles.

Profiles are code, not model output. Every field is fixed at import time; the
only runtime values are resolved from an approved ``TargetRecord``. The
``config_hash`` makes profile drift visible in artifacts and audit records.
"""

from __future__ import annotations

from huntress_contracts import (
    AssetKind,
    HttpMethod,
    OracleArchetype,
    ProfileExecutor,
    RiskClass,
    ScanWorkstream,
    SideEffectClass,
    ToolProfile,
    canonical_json,
    sha256_hex,
)

_HTTP_ASSET_KINDS = (
    AssetKind.DOMAIN,
    AssetKind.WILDCARD_DOMAIN,
    AssetKind.URL,
    AssetKind.IPV4,
    AssetKind.IPV6,
    AssetKind.CIDR,
)

_ALL_ASSET_KINDS = (
    AssetKind.DOMAIN,
    AssetKind.WILDCARD_DOMAIN,
    AssetKind.URL,
    AssetKind.IPV4,
    AssetKind.IPV6,
    AssetKind.CIDR,
)


def _profile(**kwargs: object) -> ToolProfile:
    profile = ToolProfile(
        executor=ProfileExecutor.BUILTIN,
        **kwargs,
    )
    digest = sha256_hex(canonical_json(profile.model_dump(mode="json", exclude={"config_hash"})))
    return profile.model_copy(update={"config_hash": digest})


BUILTIN_PROFILES: tuple[ToolProfile, ...] = (
    _profile(
        profile_id="http.baseline",
        version="1.0.0",
        name="HTTP baseline",
        description=(
            "Capture one unauthenticated GET response from an approved target. Establishes "
            "status, headers, body hash, and timing used as a control by later checks."
        ),
        workstream=ScanWorkstream.WEB_SURFACE,
        risk_class=RiskClass.LOW,
        side_effect_class=SideEffectClass.READ_ONLY,
        requires_approval=True,
        preauthorizable=True,
        enabled_by_default=True,
        allowed_methods=(HttpMethod.GET,),
        supported_asset_kinds=_HTTP_ASSET_KINDS,
        timeout_seconds=20,
        max_requests_per_run=1,
        builtin_handler="http_baseline",
        parser_id="http.baseline",
        tags=("http", "baseline", "passive"),
    ),
    _profile(
        profile_id="http.security_headers",
        version="1.0.0",
        name="HTTP security headers",
        description=(
            "Inspect a baseline response for missing hardening headers. This is an "
            "informational configuration observation unless impact is independently proven."
        ),
        workstream=ScanWorkstream.SIGNATURE_CHECK,
        risk_class=RiskClass.LOW,
        side_effect_class=SideEffectClass.READ_ONLY,
        requires_approval=True,
        preauthorizable=True,
        enabled_by_default=True,
        allowed_methods=(HttpMethod.GET,),
        supported_asset_kinds=_HTTP_ASSET_KINDS,
        timeout_seconds=20,
        max_requests_per_run=1,
        builtin_handler="http_security_headers",
        parser_id="http.security_headers",
        oracle_hint=OracleArchetype.CONTENT_MATCH,
        tags=("http", "headers", "configuration"),
    ),
    _profile(
        profile_id="http.exposed_files",
        version="1.0.0",
        name="Bounded sensitive-file check",
        description=(
            "Request a fixed list of common sensitive paths without path traversal. "
            "A hit is a candidate until the content-match oracle verifies the body."
        ),
        workstream=ScanWorkstream.SIGNATURE_CHECK,
        risk_class=RiskClass.LOW,
        side_effect_class=SideEffectClass.READ_ONLY,
        requires_approval=True,
        preauthorizable=True,
        enabled_by_default=True,
        allowed_methods=(HttpMethod.GET,),
        supported_asset_kinds=_HTTP_ASSET_KINDS,
        timeout_seconds=45,
        max_requests_per_run=8,
        builtin_handler="http_exposed_files",
        parser_id="http.exposed_files",
        oracle_hint=OracleArchetype.CONTENT_MATCH,
        tags=("http", "exposure", "signature"),
    ),
    _profile(
        profile_id="http.cors",
        version="1.0.0",
        name="CORS credential reflection",
        description=(
            "Send one GET with a canary Origin and check for origin reflection with "
            "Access-Control-Allow-Credentials: true."
        ),
        workstream=ScanWorkstream.SIGNATURE_CHECK,
        risk_class=RiskClass.LOW,
        side_effect_class=SideEffectClass.READ_ONLY,
        requires_approval=True,
        preauthorizable=True,
        enabled_by_default=True,
        allowed_methods=(HttpMethod.GET,),
        supported_asset_kinds=_HTTP_ASSET_KINDS,
        timeout_seconds=20,
        max_requests_per_run=1,
        builtin_handler="http_cors",
        parser_id="http.cors",
        oracle_hint=OracleArchetype.CONTENT_MATCH,
        tags=("http", "cors", "signature"),
    ),
    _profile(
        profile_id="http.open_redirect",
        version="1.0.0",
        name="Open redirect canary",
        description=(
            "Request a small fixed set of common redirect parameter names with a canary "
            "host and inspect the Location header without following redirects."
        ),
        workstream=ScanWorkstream.SIGNATURE_CHECK,
        risk_class=RiskClass.ACTIVE,
        side_effect_class=SideEffectClass.READ_ONLY,
        requires_approval=True,
        preauthorizable=False,
        enabled_by_default=False,
        allowed_methods=(HttpMethod.GET,),
        supported_asset_kinds=_HTTP_ASSET_KINDS,
        timeout_seconds=30,
        max_requests_per_run=5,
        builtin_handler="http_open_redirect",
        parser_id="http.open_redirect",
        oracle_hint=OracleArchetype.CONTENT_MATCH,
        tags=("http", "redirect", "active"),
    ),
    _profile(
        profile_id="http.reflected_marker",
        version="1.0.0",
        name="Reflected HTML marker",
        description=(
            "Send one inert HTML marker in common query parameters and detect raw "
            "reflection. The oracle does not treat reflection alone as script execution."
        ),
        workstream=ScanWorkstream.SIGNATURE_CHECK,
        risk_class=RiskClass.ACTIVE,
        side_effect_class=SideEffectClass.READ_ONLY,
        requires_approval=True,
        preauthorizable=False,
        enabled_by_default=False,
        allowed_methods=(HttpMethod.GET,),
        supported_asset_kinds=_HTTP_ASSET_KINDS,
        timeout_seconds=25,
        max_requests_per_run=2,
        builtin_handler="http_reflected_marker",
        parser_id="http.reflected_marker",
        oracle_hint=OracleArchetype.CONTENT_MATCH,
        tags=("http", "xss", "active"),
    ),
    _profile(
        profile_id="http.error_based_sqli",
        version="1.0.0",
        name="Bounded SQL error differential",
        description=(
            "Send a baseline request and three identical quote probes, then look for a "
            "database error signature absent from the baseline. No exploitation or data access."
        ),
        workstream=ScanWorkstream.SIGNATURE_CHECK,
        risk_class=RiskClass.ACTIVE,
        side_effect_class=SideEffectClass.READ_ONLY,
        requires_approval=True,
        preauthorizable=False,
        enabled_by_default=False,
        allowed_methods=(HttpMethod.GET,),
        supported_asset_kinds=_HTTP_ASSET_KINDS,
        timeout_seconds=30,
        max_requests_per_run=4,
        builtin_handler="http_error_based_sqli",
        parser_id="http.error_based_sqli",
        oracle_hint=OracleArchetype.DIFFERENTIAL_STATISTICAL,
        tags=("http", "sqli", "active", "differential"),
    ),
    _profile(
        profile_id="dns.resolve",
        version="1.0.0",
        name="DNS record resolution",
        description=(
            "Resolve A, AAAA, and CNAME records for an approved host through the configured "
            "resolver. Results are observations and never expand scope automatically."
        ),
        workstream=ScanWorkstream.PASSIVE_OSINT,
        risk_class=RiskClass.PASSIVE,
        side_effect_class=SideEffectClass.NONE,
        requires_approval=True,
        preauthorizable=True,
        enabled_by_default=True,
        allowed_methods=(HttpMethod.GET,),
        supported_asset_kinds=_ALL_ASSET_KINDS,
        timeout_seconds=15,
        max_requests_per_run=1,
        builtin_handler="dns_resolve",
        parser_id="dns.resolve",
        tags=("dns", "passive"),
    ),
)

BUILTIN_PROFILE_IDS: tuple[str, ...] = tuple(profile.profile_id for profile in BUILTIN_PROFILES)

_PROFILE_INDEX: dict[str, ToolProfile] = {profile.profile_id: profile for profile in BUILTIN_PROFILES}


def builtin_profile(profile_id: str) -> ToolProfile:
    try:
        return _PROFILE_INDEX[profile_id]
    except KeyError as exc:
        raise KeyError(f"unknown builtin profile: {profile_id}") from exc


def builtin_profiles() -> tuple[ToolProfile, ...]:
    return BUILTIN_PROFILES
