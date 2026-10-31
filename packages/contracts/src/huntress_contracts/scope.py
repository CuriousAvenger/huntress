"""Scope and authorization contracts.

A ``ScopeDocument`` is the only object that can authorize execution. It is
sealed by the governance package with an HMAC over its canonical content, and
every field is immutable. The model never constructs, mutates, or signs one.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Annotated, Self
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator

from .base import CONTRACT_VERSION, Contract, ensure_utc
from .enums import (
    AssetConfidence,
    AssetKind,
    EngagementMode,
    HttpMethod,
    RiskClass,
    ScopeStatus,
    SideEffectClass,
)

_HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.?$")
_WILDCARD_RE = re.compile(
    r"^\*\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)


def normalize_host(value: str) -> str:
    """Normalize a hostname: lower-case, IDNA, no trailing dot.

    Rejects URLs, ports, paths, userinfo, and wildcard characters here; those
    are separate asset kinds with their own validators.
    """

    host = value.strip().lower().rstrip(".")
    if not host:
        raise ValueError("host must not be empty")
    if any(ch in host for ch in "/:@?#[]* "):
        raise ValueError(f"invalid host: {value!r}")
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:  # pragma: no cover - defensive
        raise ValueError(f"invalid IDNA host: {value!r}") from exc
    if not _HOST_RE.fullmatch(ascii_host):
        raise ValueError(f"invalid hostname: {value!r}")
    return ascii_host


class AssetProvenance(Contract):
    """Where an asset came from and how much to trust it."""

    source: str = Field(min_length=1, max_length=120)
    source_ref: str | None = Field(default=None, max_length=512)
    observed_at: datetime
    confidence: AssetConfidence = AssetConfidence.CONFIRMED
    notes: str | None = Field(default=None, max_length=1000)

    _observed_utc = field_validator("observed_at")(ensure_utc)


class ScopeAsset(Contract):
    """A precisely typed matcher plus provenance and policy status."""

    asset_id: str = Field(pattern=r"^asset_[a-zA-Z0-9_-]{6,80}$")
    kind: AssetKind
    value: str = Field(min_length=1, max_length=2048)
    display_name: str | None = Field(default=None, max_length=253)
    allowed_ports: tuple[Annotated[int, Field(ge=1, le=65535)], ...] | None = None
    allowed_paths: tuple[str, ...] | None = None
    allowed_methods: tuple[HttpMethod, ...] | None = None
    provenance: AssetProvenance
    policy_status: ScopeStatus = ScopeStatus.PENDING
    expires_at: datetime | None = None
    notes: str | None = Field(default=None, max_length=1000)

    @field_validator("expires_at")
    @classmethod
    def _expires_utc(cls, value: datetime | None) -> datetime | None:
        return ensure_utc(value) if value is not None else None

    @field_validator("allowed_paths")
    @classmethod
    def _paths(cls, value: tuple[str, ...] | None) -> tuple[str, ...] | None:
        if value is None:
            return None
        for path in value:
            if not path.startswith("/") or ".." in path or "?" in path or "#" in path:
                raise ValueError(f"allowed path must be an absolute path prefix: {path!r}")
        return value

    @model_validator(mode="after")
    def _normalize_value(self) -> Self:
        kind = self.kind
        raw = self.value.strip()

        if kind is AssetKind.DOMAIN:
            normalized = normalize_host(raw)
        elif kind is AssetKind.WILDCARD_DOMAIN:
            normalized = raw.lower().rstrip(".")
            if not _WILDCARD_RE.fullmatch(normalized):
                raise ValueError(f"wildcard asset must look like *.example.com: {raw!r}")
        elif kind is AssetKind.IPV4:
            normalized = str(ipaddress.IPv4Address(raw))
        elif kind is AssetKind.IPV6:
            normalized = str(ipaddress.IPv6Address(raw))
        elif kind is AssetKind.CIDR:
            network = ipaddress.ip_network(raw, strict=True)
            normalized = str(network)
        elif kind is AssetKind.URL:
            parts = urlsplit(raw)
            if parts.scheme not in {"http", "https"}:
                raise ValueError("URL asset scheme must be http or https")
            if not parts.hostname:
                raise ValueError("URL asset requires a hostname")
            if parts.username or parts.password:
                raise ValueError("URL assets must not contain userinfo")
            if parts.query or parts.fragment:
                raise ValueError("URL assets must not contain query or fragment")
            normalized = raw
        elif kind is AssetKind.REPOSITORY:
            parts = urlsplit(raw)
            if parts.scheme not in {"https", "ssh", "git"} and not raw.startswith("git@"):
                raise ValueError("repository asset must be an https/ssh/git URL or git@host:path")
            normalized = raw.rstrip("/")
        elif kind is AssetKind.ARTIFACT:
            if not re.fullmatch(r"[a-zA-Z0-9._:/@+-]{1,512}", raw):
                raise ValueError("artifact asset contains invalid characters")
            normalized = raw
        else:  # pragma: no cover - exhaustive enum
            raise ValueError(f"unsupported asset kind: {kind}")

        object.__setattr__(self, "value", normalized)
        return self


class ScopeExclusion(Contract):
    """Exclusions always win over inclusions, at equal or broader specificity."""

    exclusion_id: str = Field(pattern=r"^excl_[a-zA-Z0-9_-]{6,80}$")
    kind: AssetKind
    value: str = Field(min_length=1, max_length=2048)
    reason: str = Field(min_length=1, max_length=500)
    created_at: datetime

    _created_utc = field_validator("created_at")(ensure_utc)

    @model_validator(mode="after")
    def _normalize(self) -> Self:
        raw = self.value.strip()
        if self.kind is AssetKind.DOMAIN:
            normalized = normalize_host(raw)
        elif self.kind is AssetKind.WILDCARD_DOMAIN:
            normalized = raw.lower().rstrip(".")
            if not _WILDCARD_RE.fullmatch(normalized):
                raise ValueError(f"wildcard exclusion must look like *.example.com: {raw!r}")
        elif self.kind is AssetKind.CIDR:
            normalized = str(ipaddress.ip_network(raw, strict=True))
        elif self.kind in {AssetKind.IPV4, AssetKind.IPV6}:
            normalized = str(ipaddress.ip_address(raw))
        else:
            normalized = raw
        object.__setattr__(self, "value", normalized)
        return self


class RateLimits(Contract):
    """Per-engagement and per-host request ceilings, enforced by the executor."""

    per_host_requests_per_minute: int = Field(default=30, ge=1, le=600)
    per_engagement_requests_per_minute: int = Field(default=60, ge=1, le=3000)
    max_concurrency: int = Field(default=2, ge=1, le=16)
    max_requests_per_profile: int = Field(default=50, ge=1, le=1000)


class TestingWindow(Contract):
    """Authorization window. Execution and validation both re-check it."""

    starts_at: datetime
    ends_at: datetime

    _window_utc = field_validator("starts_at", "ends_at")(ensure_utc)

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if self.ends_at <= self.starts_at:
            raise ValueError("testing window ends_at must be after starts_at")
        return self

    def contains(self, moment: datetime) -> bool:
        return self.starts_at <= ensure_utc(moment) <= self.ends_at


class ROEConstraints(Contract):
    """Rules of engagement compiled into deterministic checks."""

    max_risk_class: RiskClass = RiskClass.LOW
    allowed_side_effects: tuple[SideEffectClass, ...] = (
        SideEffectClass.NONE,
        SideEffectClass.READ_ONLY,
    )
    allow_detect_only: bool = False
    allow_exploit_like: bool = False
    allow_availability_testing: bool = False
    max_requests_per_host: int = Field(default=500, ge=1, le=100_000)
    data_handling: str = Field(default="minimize; redact secrets; retain 90 days", max_length=1000)
    notes: str = Field(default="", max_length=4000)


class ReportingRules(Contract):
    """Program reporting terms. Submission is always human-approved."""

    platform: str = Field(default="none", max_length=80)
    disclosure_policy: str = Field(default="coordinated", max_length=120)
    contact: str | None = Field(default=None, max_length=320)
    report_language: str = Field(default="en", max_length=16)
    auto_submit_allowed: bool = False
    notes: str = Field(default="", max_length=2000)


class ScopeDraft(Contract):
    """Operator input to the scope compiler, before human approval and sealing."""

    engagement_id: str = Field(pattern=r"^eng_[a-zA-Z0-9_-]{6,80}$")
    program_id: str = Field(min_length=1, max_length=120)
    mode: EngagementMode
    assets: tuple[ScopeAsset, ...] = Field(min_length=1)
    exclusions: tuple[ScopeExclusion, ...] = ()
    allowed_methods: tuple[HttpMethod, ...] = (HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS)
    allowed_profiles: tuple[str, ...] = Field(min_length=1)
    preapproved_profiles: tuple[str, ...] = ()
    rate_limits: RateLimits = RateLimits()
    testing_window: TestingWindow
    roe: ROEConstraints = ROEConstraints()
    reporting: ReportingRules = ReportingRules()
    authorization_ref: str = Field(min_length=1, max_length=512)
    source_format: str = Field(default="manual", max_length=40)
    allow_public_lab: bool = Field(
        default=False,
        description=(
            "Lab mode only: permit non-private/public targets (e.g. an HTB box) "
            "with recorded authorization"
        ),
    )
    notes: str = Field(default="", max_length=4000)

    @model_validator(mode="after")
    def _draft_invariants(self) -> Self:
        asset_ids = [a.asset_id for a in self.assets]
        if len(asset_ids) != len(set(asset_ids)):
            raise ValueError("duplicate asset_id in scope")
        if len(set(self.allowed_profiles)) != len(self.allowed_profiles):
            raise ValueError("duplicate allowed profile")
        unknown = set(self.preapproved_profiles) - set(self.allowed_profiles)
        if unknown:
            raise ValueError(f"preapproved profiles must also be allowed: {sorted(unknown)}")
        if self.mode is EngagementMode.LAB:
            return self
        if not self.roe.allow_availability_testing:
            pass
        if self.roe.allow_availability_testing:
            raise ValueError("availability testing is disabled in this release")
        return self


class ScopeDocument(Contract):
    """A sealed, human-approved authorization record.

    ``signature`` is an HMAC-SHA256 over ``content_hash``. ``content_hash``
    covers every other field, including the approval identity and window.
    """

    schema_version: str = CONTRACT_VERSION
    scope_id: str = Field(pattern=r"^scope_[a-zA-Z0-9_-]{6,80}$")
    engagement_id: str = Field(pattern=r"^eng_[a-zA-Z0-9_-]{6,80}$")
    program_id: str
    mode: EngagementMode
    version: int = Field(ge=1)
    assets: tuple[ScopeAsset, ...]
    exclusions: tuple[ScopeExclusion, ...]
    allowed_methods: tuple[HttpMethod, ...]
    allowed_profiles: tuple[str, ...]
    preapproved_profiles: tuple[str, ...]
    rate_limits: RateLimits
    testing_window: TestingWindow
    roe: ROEConstraints
    reporting: ReportingRules
    authorization_ref: str
    source_format: str
    allow_public_lab: bool = False
    notes: str
    approved_by: str = Field(min_length=1, max_length=200)
    approved_at: datetime
    approval_note: str = Field(default="", max_length=2000)
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")
    seal_version: str = "hmac-sha256-v1"

    _approved_utc = field_validator("approved_at")(ensure_utc)

    @property
    def approved_asset_ids(self) -> frozenset[str]:
        return frozenset(a.asset_id for a in self.assets if a.policy_status is ScopeStatus.APPROVED)

    def is_expired(self, now: datetime) -> bool:
        return not self.testing_window.contains(now)

    def asset(self, asset_id: str) -> ScopeAsset | None:
        return next((a for a in self.assets if a.asset_id == asset_id), None)

    def signing_payload(self) -> str:
        return self.content_hash
