"""Immutable artifact-reference contracts.

Artifact identifiers are SHA-256 content hashes. Raw bytes live in the
content-addressed store; these records are the provenance index.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, field_validator, model_validator

from .base import Contract, ensure_utc
from .enums import RedactionStatus


class ArtifactRef(Contract):
    """A stable, hash-addressed pointer. Never embeds the artifact body."""

    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    media_type: str = Field(default="application/octet-stream", max_length=120)
    size_bytes: int = Field(ge=0)
    created_at: datetime
    redaction_status: RedactionStatus = RedactionStatus.RAW
    parent_refs: tuple[str, ...] = ()

    _created_utc = field_validator("created_at")(ensure_utc)

    @property
    def ref(self) -> str:
        return self.sha256


class ArtifactProvenance(Contract):
    """Who produced an artifact, with what tool, and under which policy."""

    engagement_id: str | None = Field(default=None, pattern=r"^eng_[a-zA-Z0-9_-]{6,80}$")
    target_id: str | None = Field(default=None, pattern=r"^tgt_[a-zA-Z0-9_-]{6,80}$")
    asset_id: str | None = Field(default=None, pattern=r"^asset_[a-zA-Z0-9_-]{6,80}$")
    acquisition_time: datetime
    source_tool: str = Field(min_length=1, max_length=200)
    tool_version: str = Field(default="unknown", max_length=80)
    profile_id: str | None = Field(default=None, max_length=120)
    action_request_id: str | None = Field(default=None, max_length=80)
    policy_version: str | None = Field(default=None, max_length=80)
    scope_hash: str | None = Field(default=None, max_length=64)
    exit_status: int | None = None
    redaction_status: RedactionStatus = RedactionStatus.RAW
    storage_key: str = Field(default="", max_length=512)
    media_type: str = Field(default="application/octet-stream", max_length=120)
    size_bytes: int = Field(default=0, ge=0)
    parent_refs: tuple[str, ...] = ()
    note: str = Field(default="", max_length=1000)

    _acquisition_utc = field_validator("acquisition_time")(ensure_utc)


class ArtifactMetadata(Contract):
    """The complete index record for one stored artifact."""

    ref: ArtifactRef
    provenance: tuple[ArtifactProvenance, ...] = Field(min_length=1)
    storage_key: str = Field(min_length=1, max_length=512)

    @model_validator(mode="after")
    def _consistent(self) -> ArtifactMetadata:
        if self.storage_key != self.ref.sha256:
            raise ValueError("storage_key must equal the content hash")
        if any(p.size_bytes not in (0, self.ref.size_bytes) for p in self.provenance):
            raise ValueError("provenance size disagrees with artifact ref")
        return self
