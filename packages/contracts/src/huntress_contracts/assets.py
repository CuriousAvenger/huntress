"""Asset inventory and target contracts.

Targets are derived from approved scope assets by deterministic discovery.
The model may reference a ``target_id``; it may never supply a host or URL for
execution.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, field_validator, model_validator

from .base import Contract, ensure_utc
from .enums import AssetConfidence, AssetKind
from .scope import normalize_host


class TechFingerprint(Contract):
    """A technology observation with source and confidence."""

    name: str = Field(min_length=1, max_length=120)
    version: str | None = Field(default=None, max_length=120)
    category: str = Field(default="unknown", max_length=80)
    source: str = Field(min_length=1, max_length=120)
    confidence: AssetConfidence = AssetConfidence.PROBABLE
    evidence_ref: str | None = Field(default=None, max_length=128)


class TargetRecord(Contract):
    """A concrete, resolvable target derived from one approved scope asset.

    ``in_scope`` is a cached view. The policy gateway still recomputes scope
    immediately before every execution; this flag is never authority.
    """

    target_id: str = Field(pattern=r"^tgt_[a-zA-Z0-9_-]{6,80}$")
    engagement_id: str = Field(pattern=r"^eng_[a-zA-Z0-9_-]{6,80}$")
    asset_id: str = Field(pattern=r"^asset_[a-zA-Z0-9_-]{6,80}$")
    asset_kind: AssetKind
    host: str
    scheme: str = Field(default="https", pattern=r"^https?$")
    port: int = Field(default=443, ge=1, le=65535)
    base_url: str
    resolved_ips: tuple[str, ...] = ()
    cnames: tuple[str, ...] = ()
    technologies: tuple[TechFingerprint, ...] = ()
    source: str = Field(min_length=1, max_length=120)
    confidence: AssetConfidence = AssetConfidence.CONFIRMED
    first_seen: datetime
    last_seen: datetime
    in_scope: bool = True
    notes: str = Field(default="", max_length=1000)

    _seen_utc = field_validator("first_seen", "last_seen")(ensure_utc)

    @field_validator("host")
    @classmethod
    def _host(cls, value: str) -> str:
        return normalize_host(value)

    @model_validator(mode="after")
    def _url_consistent(self) -> TargetRecord:
        if self.base_url.startswith(("http://", "https://")) is False:
            raise ValueError("base_url must be absolute http(s)")
        if " " in self.base_url or "\n" in self.base_url:
            raise ValueError("base_url must not contain whitespace")
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must not precede first_seen")
        return self


class AssetInventory(Contract):
    """A point-in-time inventory snapshot for one engagement."""

    engagement_id: str = Field(pattern=r"^eng_[a-zA-Z0-9_-]{6,80}$")
    targets: tuple[TargetRecord, ...] = ()
    generated_at: datetime
    source_digest: str = Field(default="", max_length=128)

    _generated_utc = field_validator("generated_at")(ensure_utc)

    def by_id(self, target_id: str) -> TargetRecord | None:
        return next((t for t in self.targets if t.target_id == target_id), None)

    def by_host(self, host: str) -> tuple[TargetRecord, ...]:
        normalized = normalize_host(host)
        return tuple(t for t in self.targets if t.host == normalized)
