"""Reviewed execution profiles and the immutable profile registry.

Profiles are code-reviewed configuration. The model may only reference a
profile ID; it can never supply a command, argument, target, or timeout.
Exegol profiles use a strict argv template with server-side placeholders that
are resolved from the authoritative ``TargetRecord``.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterable

from huntress_contracts import (
    AssetKind,
    HttpMethod,
    OracleArchetype,
    ProfileExecutor,
    RiskClass,
    ScanWorkstream,
    SideEffectClass,
    TargetRecord,
    ToolProfile,
    canonical_json,
    sha256_hex,
)
from huntress_scanning import BUILTIN_PROFILES as SCANNING_BUILTIN_PROFILES

_PLACEHOLDER_RE = re.compile(r"\{([a-z_]+)\}")
_ALLOWED_PLACEHOLDERS = frozenset({"host", "port", "scheme", "base_url", "asset_id", "target_id"})
_TARGET_PLACEHOLDERS = frozenset({"host", "base_url"})
_FORBIDDEN_TEMPLATE_CHARS = frozenset(";|&$`<>()\\\n\r\0")

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
        executor=ProfileExecutor.EXEGOL,
        **kwargs,
    )
    digest = sha256_hex(canonical_json(profile.model_dump(mode="json", exclude={"config_hash"})))
    return profile.model_copy(update={"config_hash": digest})


EXEGOL_PROFILES: tuple[ToolProfile, ...] = (
    _profile(
        profile_id="exegol.curl_headers",
        version="1.0.0",
        name="Exegol curl header capture",
        description=(
            "Capture response headers from an approved URL with curl inside the isolated "
            "Exegol container. The URL is resolved from the target record and shell-quoted."
        ),
        workstream=ScanWorkstream.WEB_SURFACE,
        risk_class=RiskClass.LOW,
        side_effect_class=SideEffectClass.READ_ONLY,
        requires_approval=True,
        preauthorizable=False,
        enabled_by_default=False,
        allowed_methods=(HttpMethod.GET,),
        supported_asset_kinds=_HTTP_ASSET_KINDS,
        timeout_seconds=60,
        max_output_bytes=262_144,
        max_requests_per_run=1,
        argv_template=(
            "curl",
            "-sS",
            "-D",
            "-",
            "-o",
            "/dev/null",
            "--max-time",
            "20",
            "{base_url}",
        ),
        parser_id="exegol.curl_headers",
        oracle_hint=OracleArchetype.CONTENT_MATCH,
        tags=("exegol", "http", "headers"),
    ),
    _profile(
        profile_id="exegol.whatweb",
        version="1.0.0",
        name="Exegol WhatWeb fingerprint",
        description=(
            "Run WhatWeb with color and verbose output disabled against an approved URL. "
            "Output is an observation, never automatic scope expansion."
        ),
        workstream=ScanWorkstream.SIGNATURE_CHECK,
        risk_class=RiskClass.LOW,
        side_effect_class=SideEffectClass.READ_ONLY,
        requires_approval=True,
        preauthorizable=False,
        enabled_by_default=False,
        allowed_methods=(HttpMethod.GET,),
        supported_asset_kinds=_HTTP_ASSET_KINDS,
        timeout_seconds=90,
        max_output_bytes=262_144,
        max_requests_per_run=1,
        argv_template=("whatweb", "--no-color", "--quiet", "{base_url}"),
        parser_id="exegol.whatweb",
        oracle_hint=OracleArchetype.COMPONENT_MATCH,
        tags=("exegol", "fingerprint", "web"),
    ),
    _profile(
        profile_id="exegol.nmap_top_ports",
        version="1.0.0",
        name="Exegol bounded TCP top-ports scan",
        description=(
            "Scan the top 100 TCP ports of an approved host with nmap connect scans. "
            "No service/version detection, no scripts, and a fixed host timeout."
        ),
        workstream=ScanWorkstream.ACTIVE_ENUMERATION,
        risk_class=RiskClass.ACTIVE,
        side_effect_class=SideEffectClass.NONE,
        requires_approval=True,
        preauthorizable=False,
        enabled_by_default=False,
        allowed_methods=(HttpMethod.GET,),
        supported_asset_kinds=_ALL_ASSET_KINDS,
        timeout_seconds=300,
        max_output_bytes=1_048_576,
        max_requests_per_run=100,
        argv_template=(
            "nmap",
            "-Pn",
            "-sT",
            "--top-ports",
            "100",
            "--host-timeout",
            "120s",
            "{host}",
        ),
        parser_id="exegol.nmap_top_ports",
        oracle_hint=None,
        tags=("exegol", "network", "nmap", "active"),
    ),
    _profile(
        profile_id="exegol.nuclei_safe",
        version="1.0.0",
        name="Exegol low-impact Nuclei templates",
        description=(
            "Run Nuclei limited to exposure, technology, and misconfiguration tags while "
            "excluding intrusive, denial-of-service, and fuzzing templates. Rate limited."
        ),
        workstream=ScanWorkstream.SIGNATURE_CHECK,
        risk_class=RiskClass.ACTIVE,
        side_effect_class=SideEffectClass.READ_ONLY,
        requires_approval=True,
        preauthorizable=False,
        enabled_by_default=False,
        allowed_methods=(HttpMethod.GET,),
        supported_asset_kinds=_HTTP_ASSET_KINDS,
        timeout_seconds=300,
        max_output_bytes=1_048_576,
        max_requests_per_run=50,
        argv_template=(
            "nuclei",
            "-u",
            "{base_url}",
            "-tags",
            "exposure,tech,misconfig",
            "-etags",
            "intrusive,dos,fuzz",
            "-severity",
            "low,medium,high,critical",
            "-rate-limit",
            "10",
            "-silent",
            "-no-color",
            "-disable-update-check",
        ),
        parser_id="exegol.nuclei_safe",
        oracle_hint=OracleArchetype.CONTENT_MATCH,
        tags=("exegol", "nuclei", "signature", "active"),
    ),
)

ALL_PROFILES: tuple[ToolProfile, ...] = (*SCANNING_BUILTIN_PROFILES, *EXEGOL_PROFILES)
ALL_PROFILE_IDS: tuple[str, ...] = tuple(profile.profile_id for profile in ALL_PROFILES)


def _config_digest(profile: ToolProfile) -> str:
    return sha256_hex(canonical_json(profile.model_dump(mode="json", exclude={"config_hash"})))


def validate_argv_template(profile: ToolProfile) -> None:
    """Reject templates that could escape the fixed operation envelope."""

    if profile.executor is not ProfileExecutor.EXEGOL:
        return
    placeholders: set[str] = set()
    for token in profile.argv_template:
        if not token:
            raise ValueError(f"profile {profile.profile_id} has an empty argv token")
        for char in token:
            if char in _FORBIDDEN_TEMPLATE_CHARS:
                raise ValueError(
                    f"profile {profile.profile_id} argv token contains forbidden character "
                    f"{char!r}"
                )
        for name in _PLACEHOLDER_RE.findall(token):
            if name not in _ALLOWED_PLACEHOLDERS:
                raise ValueError(
                    f"profile {profile.profile_id} uses unknown placeholder {{{name}}}"
                )
            placeholders.add(name)
        remainder = _PLACEHOLDER_RE.sub("", token)
        if "{" in remainder or "}" in remainder:
            raise ValueError(f"profile {profile.profile_id} has a malformed placeholder")
    if not placeholders & _TARGET_PLACEHOLDERS:
        raise ValueError(
            f"profile {profile.profile_id} must resolve a target placeholder "
            f"({', '.join(sorted(_TARGET_PLACEHOLDERS))})"
        )


def resolve_argv(profile: ToolProfile, target: TargetRecord) -> tuple[str, ...]:
    """Resolve server-side placeholders and shell-quote every token."""

    values = {
        "host": target.host,
        "port": str(target.port),
        "scheme": target.scheme,
        "base_url": target.base_url,
        "asset_id": target.asset_id,
        "target_id": target.target_id,
    }
    resolved: list[str] = []
    for token in profile.argv_template:
        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            try:
                return values[name]
            except KeyError as exc:  # pragma: no cover - validated at registration
                raise ValueError(f"unresolvable placeholder {{{name}}}") from exc

        value = _PLACEHOLDER_RE.sub(replace, token)
        if any(char in value for char in "\n\r\0"):
            raise ValueError(f"profile {profile.profile_id} resolved a control character")
        resolved.append(value)
    return tuple(resolved)


def build_command(profile: ToolProfile, target: TargetRecord) -> str:
    """Return a shell-safe command string for the fixed Exegol profile."""

    return shlex.join(resolve_argv(profile, target))


class ProfileRegistry:
    """Immutable, duplicate-free registry of reviewed profiles."""

    def __init__(self, profiles: Iterable[ToolProfile] = ALL_PROFILES) -> None:
        index: dict[str, ToolProfile] = {}
        for profile in profiles:
            if profile.profile_id in index:
                raise ValueError(f"duplicate profile id: {profile.profile_id}")
            digest = _config_digest(profile)
            if profile.config_hash and profile.config_hash != digest:
                raise ValueError(f"profile {profile.profile_id} config hash does not match its body")
            validate_argv_template(profile)
            index[profile.profile_id] = profile.model_copy(update={"config_hash": digest})
        if not index:
            raise ValueError("profile registry must not be empty")
        self._profiles = index

    def get(self, profile_id: str) -> ToolProfile | None:
        return self._profiles.get(profile_id)

    def require(self, profile_id: str) -> ToolProfile:
        from .errors import ProfileUnknown

        profile = self.get(profile_id)
        if profile is None:
            raise ProfileUnknown(f"unknown execution profile: {profile_id}")
        return profile

    def all(self) -> tuple[ToolProfile, ...]:
        return tuple(self._profiles.values())

    def ids(self) -> tuple[str, ...]:
        return tuple(self._profiles)

    def by_executor(self, executor: ProfileExecutor) -> tuple[ToolProfile, ...]:
        return tuple(p for p in self._profiles.values() if p.executor is executor)


DEFAULT_PROFILE_REGISTRY = ProfileRegistry()


def all_profiles() -> tuple[ToolProfile, ...]:
    return DEFAULT_PROFILE_REGISTRY.all()


def profile(profile_id: str) -> ToolProfile:
    return DEFAULT_PROFILE_REGISTRY.require(profile_id)
