"""Deterministic scope compilation and enforcement.

Two rules drive this module:

1. Ambiguity is denial. Missing, pending, expired, unsigned, or contradictory
   scope data never authorizes an action.
2. Matching is exact. Wildcards match subdomains only, exclusions always win,
   and redirects never expand scope.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlsplit

from huntress_contracts import (
    Engagement,
    HttpMethod,
    ReasonCode,
    RiskClass,
    ScopeAsset,
    ScopeDocument,
    ScopeDraft,
    ScopeStatus,
    SideEffectClass,
    TargetRecord,
    ToolProfile,
    ensure_utc,
    model_self_hash,
    new_id,
    risk_rank,
    side_effect_rank,
    utc_now,
)

from .errors import ScopeCompileError
from .hashing import scope_content_hash, sign, verify_scope_seal

_LAB_SUFFIXES = (".localhost", ".local", ".test", ".invalid", ".example", ".internal")


@dataclass(frozen=True, slots=True)
class ScopeCheck:
    allowed: bool
    reason_code: ReasonCode
    reasons: tuple[str, ...]
    asset_id: str | None = None


def _deny(code: ReasonCode, *reasons: str) -> ScopeCheck:
    return ScopeCheck(False, code, reasons)


def _allow(asset_id: str | None, *reasons: str) -> ScopeCheck:
    return ScopeCheck(True, ReasonCode.ALLOWED, reasons, asset_id)


def _is_lab_safe_host(host: str) -> bool:
    normalized = host.lower().rstrip(".")
    if normalized == "localhost" or normalized.endswith(_LAB_SUFFIXES):
        return True
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return "." not in normalized
    return address.is_loopback or address.is_private or address.is_link_local


def _is_lab_safe_asset(asset: ScopeAsset) -> bool:
    kind = asset.kind.value
    if kind in {"repository", "artifact"}:
        return True
    if kind in {"domain", "wildcard_domain"}:
        base = asset.value.removeprefix("*.")
        return _is_lab_safe_host(base)
    if kind in {"ipv4", "ipv6"}:
        address = ipaddress.ip_address(asset.value)
        return address.is_loopback or address.is_private or address.is_link_local
    if kind == "cidr":
        network = ipaddress.ip_network(asset.value)
        return network.is_loopback or network.is_private or network.is_link_local
    if kind == "url":
        host = urlsplit(asset.value).hostname or ""
        return _is_lab_safe_host(host)
    return False


def _asset_matches_url(asset: ScopeAsset, url: str) -> bool:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return False
    host = parts.hostname.lower().rstrip(".")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    kind = asset.kind.value

    if kind == "domain":
        return host == asset.value
    if kind == "wildcard_domain":
        base_host = asset.value.removeprefix("*.")
        return host.endswith(f".{base_host}") and host != base_host
    if kind == "ipv4":
        return host == asset.value
    if kind == "ipv6":
        try:
            return ipaddress.ip_address(host) == ipaddress.ip_address(asset.value)
        except ValueError:
            return False
    if kind == "cidr":
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(asset.value)
        except ValueError:
            return False
    if kind == "url":
        base_parts = urlsplit(asset.value)
        base_port = base_parts.port or (443 if base_parts.scheme == "https" else 80)
        if (parts.scheme, host, port) != (
            base_parts.scheme,
            (base_parts.hostname or "").lower(),
            base_port,
        ):
            return False
        base_path = base_parts.path or "/"
        return path == base_path or path.startswith(base_path.rstrip("/") + "/")
    return False


def _target_path(target: TargetRecord) -> str:
    return urlsplit(target.base_url).path or "/"


def _asset_matches_target(asset: ScopeAsset, target: TargetRecord) -> bool:
    kind = asset.kind.value
    if kind in {"repository", "artifact"}:
        return False
    if kind in {"ipv4", "ipv6", "cidr"}:
        candidates = {target.host, *target.resolved_ips}
        if kind == "ipv4":
            return asset.value in candidates
        if kind == "ipv6":
            try:
                wanted = ipaddress.ip_address(asset.value)
            except ValueError:
                return False
            for candidate in candidates:
                try:
                    if ipaddress.ip_address(candidate) == wanted:
                        return True
                except ValueError:
                    continue
            return False
        network = ipaddress.ip_network(asset.value)
        for candidate in candidates:
            try:
                if ipaddress.ip_address(candidate) in network:
                    return True
            except ValueError:
                continue
        return False
    return _asset_matches_url(asset, target.base_url)


def _exclusion_matches_target(exclusion_kind: str, exclusion_value: str, target: TargetRecord) -> bool:
    if exclusion_kind == "domain":
        return target.host == exclusion_value
    if exclusion_kind == "wildcard_domain":
        base = exclusion_value.removeprefix("*.")
        return target.host.endswith(f".{base}") and target.host != base
    if exclusion_kind in {"ipv4", "ipv6"}:
        return exclusion_value in {target.host, *target.resolved_ips}
    if exclusion_kind == "cidr":
        network = ipaddress.ip_network(exclusion_value)
        for candidate in {target.host, *target.resolved_ips}:
            try:
                if ipaddress.ip_address(candidate) in network:
                    return True
            except ValueError:
                continue
        return False
    if exclusion_kind == "url":
        return target.base_url == exclusion_value or target.base_url.startswith(
            exclusion_value.rstrip("/") + "/"
        )
    return False


def _exclusion_matches_url(exclusion_kind: str, exclusion_value: str, url: str) -> bool:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().rstrip(".")
    if exclusion_kind == "domain":
        return host == exclusion_value
    if exclusion_kind == "wildcard_domain":
        base = exclusion_value.removeprefix("*.")
        return host.endswith(f".{base}") and host != base
    if exclusion_kind in {"ipv4", "ipv6"}:
        return host == exclusion_value
    if exclusion_kind == "cidr":
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(exclusion_value)
        except ValueError:
            return False
    if exclusion_kind == "url":
        return url == exclusion_value or url.startswith(exclusion_value.rstrip("/") + "/")
    return False


class ScopeCompiler:
    """Validate a draft, freeze it, and seal it with a local HMAC key."""

    def __init__(self, signing_key: bytes) -> None:
        if len(signing_key) < 32:
            raise ValueError("signing key must be at least 32 bytes")
        self._key = signing_key

    def compile(
        self,
        draft: ScopeDraft,
        *,
        profiles: tuple[ToolProfile, ...],
        approved_by: str,
        approved_at: datetime | None = None,
        scope_id: str | None = None,
        version: int = 1,
        approval_note: str = "",
    ) -> ScopeDocument:
        now = ensure_utc(approved_at) if approved_at is not None else utc_now()
        self._validate(draft, profiles, now)

        approved_assets = tuple(
            asset.model_copy(update={"policy_status": ScopeStatus.APPROVED}) for asset in draft.assets
        )
        scope = ScopeDocument(
            scope_id=scope_id or new_id("scope"),
            engagement_id=draft.engagement_id,
            program_id=draft.program_id,
            mode=draft.mode,
            version=version,
            assets=approved_assets,
            exclusions=draft.exclusions,
            allowed_methods=draft.allowed_methods,
            allowed_profiles=draft.allowed_profiles,
            preapproved_profiles=draft.preapproved_profiles,
            rate_limits=draft.rate_limits,
            testing_window=draft.testing_window,
            roe=draft.roe,
            reporting=draft.reporting,
            authorization_ref=draft.authorization_ref,
            source_format=draft.source_format,
            allow_public_lab=draft.allow_public_lab,
            notes=draft.notes,
            approved_by=approved_by,
            approved_at=now,
            approval_note=approval_note,
            content_hash="0" * 64,
            signature="0" * 64,
        )
        digest = scope_content_hash(scope)
        sealed = scope.model_copy(update={"content_hash": digest, "signature": sign(self._key, digest)})
        return sealed

    def _validate(self, draft: ScopeDraft, profiles: tuple[ToolProfile, ...], now: datetime) -> None:
        if not draft.assets:
            raise ScopeCompileError("scope must contain at least one asset")
        if draft.testing_window.ends_at <= now:
            raise ScopeCompileError("testing window has already ended")
        if draft.mode.value == "lab" and not draft.allow_public_lab:
            unsafe = [asset.asset_id for asset in draft.assets if not _is_lab_safe_asset(asset)]
            if unsafe:
                raise ScopeCompileError(
                    "lab mode only accepts loopback/private/.test/.local targets unless "
                    f"allow_public_lab is explicitly set; unsafe assets: {unsafe}"
                )
        for asset in draft.assets:
            if asset.expires_at is not None and asset.expires_at <= now:
                raise ScopeCompileError(f"asset {asset.asset_id} is already expired")

        catalog = {profile.profile_id: profile for profile in profiles}
        missing = sorted(set(draft.allowed_profiles) - set(catalog))
        if missing:
            raise ScopeCompileError(f"unknown allowed profiles: {missing}")
        for profile_id in draft.allowed_profiles:
            profile = catalog[profile_id]
            if risk_rank(profile.risk_class) > risk_rank(draft.roe.max_risk_class):
                raise ScopeCompileError(
                    f"profile {profile_id} risk {profile.risk_class} exceeds ROE max "
                    f"{draft.roe.max_risk_class}"
                )
            if profile.side_effect_class not in draft.roe.allowed_side_effects:
                raise ScopeCompileError(
                    f"profile {profile_id} side effect {profile.side_effect_class} is not allowed"
                )
            if not set(profile.allowed_methods).issubset(set(draft.allowed_methods)):
                raise ScopeCompileError(f"profile {profile_id} uses methods outside the scope allowlist")
            if profile.risk_class is RiskClass.EXPLOIT_LIKE and not draft.roe.allow_exploit_like:
                raise ScopeCompileError(f"profile {profile_id} is exploit-like but ROE forbids it")
            if "availability" in profile.tags and not draft.roe.allow_availability_testing:
                raise ScopeCompileError(f"profile {profile_id} is availability-affecting; disabled")

        for profile_id in draft.preapproved_profiles:
            profile = catalog[profile_id]
            if not profile.preauthorizable:
                raise ScopeCompileError(f"profile {profile_id} cannot be preauthorized")
            if risk_rank(profile.risk_class) > risk_rank(RiskClass.LOW):
                raise ScopeCompileError(f"profile {profile_id} is too risky to preauthorize")
            if side_effect_rank(profile.side_effect_class) > side_effect_rank(SideEffectClass.READ_ONLY):
                raise ScopeCompileError(f"profile {profile_id} has side effects and cannot be preauthorized")


class ScopeGuard:
    """Recompute authorization immediately before every execution."""

    def check_target(
        self,
        *,
        engagement: Engagement,
        scope: ScopeDocument,
        target: TargetRecord,
        method: HttpMethod,
        now: datetime,
        signing_key: bytes,
    ) -> ScopeCheck:
        moment = ensure_utc(now)
        if engagement.engagement_id != scope.engagement_id:
            return _deny(ReasonCode.DENIED_SCOPE_MISSING, "scope belongs to a different engagement")
        if engagement.mode is not scope.mode:
            return _deny(ReasonCode.DENIED_SCOPE_INTEGRITY, "engagement mode does not match scope mode")
        if scope.approved_by is None or not scope.approved_by:
            return _deny(ReasonCode.DENIED_SCOPE_NOT_APPROVED, "scope has no human approver")
        if any(asset.policy_status is not ScopeStatus.APPROVED for asset in scope.assets):
            return _deny(ReasonCode.DENIED_SCOPE_NOT_APPROVED, "scope contains unapproved assets")
        if not verify_scope_seal(scope, signing_key):
            return _deny(ReasonCode.DENIED_SCOPE_INTEGRITY, "scope seal is invalid")
        if not scope.testing_window.contains(moment):
            return _deny(ReasonCode.DENIED_SCOPE_EXPIRED, "testing window is not active")
        if target.engagement_id != engagement.engagement_id:
            return _deny(ReasonCode.DENIED_TARGET_NOT_FOUND, "target belongs to a different engagement")
        if not target.in_scope:
            return _deny(ReasonCode.DENIED_TARGET_OUT_OF_SCOPE, "target is marked out of scope")

        for exclusion in scope.exclusions:
            if _exclusion_matches_target(exclusion.kind.value, exclusion.value, target):
                return _deny(
                    ReasonCode.DENIED_TARGET_EXCLUDED,
                    f"target matches exclusion {exclusion.exclusion_id}: {exclusion.reason}",
                )

        asset = scope.asset(target.asset_id)
        if asset is None:
            return _deny(ReasonCode.DENIED_TARGET_OUT_OF_SCOPE, "target references no scope asset")
        if asset.expires_at is not None and asset.expires_at <= moment:
            return _deny(ReasonCode.DENIED_SCOPE_EXPIRED, f"asset {asset.asset_id} has expired")
        if not _asset_matches_target(asset, target):
            return _deny(
                ReasonCode.DENIED_TARGET_OUT_OF_SCOPE,
                f"target does not match scope asset {asset.asset_id}",
            )
        if asset.allowed_ports is not None and target.port not in asset.allowed_ports:
            return _deny(ReasonCode.DENIED_TARGET_OUT_OF_SCOPE, "target port is not allowed")
        if asset.allowed_paths is not None:
            path = _target_path(target)
            if not any(path == p or path.startswith(p.rstrip("/") + "/") for p in asset.allowed_paths):
                return _deny(ReasonCode.DENIED_TARGET_OUT_OF_SCOPE, "target path is not allowed")
        if method not in scope.allowed_methods:
            return _deny(ReasonCode.DENIED_METHOD_NOT_ALLOWED, f"method {method} is not allowed")
        if asset.allowed_methods is not None and method not in asset.allowed_methods:
            return _deny(ReasonCode.DENIED_METHOD_NOT_ALLOWED, f"method {method} is not allowed for asset")
        return _allow(asset.asset_id, "scope, target, window, method, and seal verified")

    def check_redirect(
        self,
        *,
        scope: ScopeDocument,
        url: str,
        method: HttpMethod,
        now: datetime,
        signing_key: bytes,
    ) -> ScopeCheck:
        """A redirect target is a candidate, never automatic scope expansion."""

        if not verify_scope_seal(scope, signing_key):
            return _deny(ReasonCode.DENIED_SCOPE_INTEGRITY, "scope seal is invalid")
        if not scope.testing_window.contains(ensure_utc(now)):
            return _deny(ReasonCode.DENIED_SCOPE_EXPIRED, "testing window is not active")
        if method not in scope.allowed_methods:
            return _deny(ReasonCode.DENIED_METHOD_NOT_ALLOWED, f"method {method} is not allowed")
        for exclusion in scope.exclusions:
            if _exclusion_matches_url(exclusion.kind.value, exclusion.value, url):
                return _deny(ReasonCode.DENIED_TARGET_EXCLUDED, "redirect target is excluded")
        for asset in scope.assets:
            if asset.policy_status is not ScopeStatus.APPROVED:
                continue
            if not _asset_matches_url(asset, url):
                continue
            parts = urlsplit(url)
            port = parts.port or (443 if parts.scheme == "https" else 80)
            if asset.allowed_ports is not None and port not in asset.allowed_ports:
                continue
            if asset.allowed_paths is not None:
                path = parts.path or "/"
                if not any(path == p or path.startswith(p.rstrip("/") + "/") for p in asset.allowed_paths):
                    continue
            return _allow(asset.asset_id, "redirect target matched an approved asset")
        return _deny(ReasonCode.DENIED_REDIRECT_NOT_IN_SCOPE, "redirect target is outside approved scope")

    def url_in_scope(
        self,
        *,
        scope: ScopeDocument,
        url: str,
        method: HttpMethod,
        now: datetime,
        signing_key: bytes,
    ) -> bool:
        return self.check_redirect(
            scope=scope, url=url, method=method, now=now, signing_key=signing_key
        ).allowed


def scope_fingerprint(scope: ScopeDocument) -> str:
    """Hash used by budgets, approvals, and decision records."""

    return model_self_hash(scope, exclude=frozenset({"content_hash", "signature"}))
