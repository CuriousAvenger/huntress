"""Immutable, content-addressed artifact storage.

Layout::

    <root>/objects/<aa>/<bb>/<sha256>          raw bytes
    <root>/objects/<aa>/<bb>/<sha256>.json     provenance metadata
    <root>/tmp/                                atomic staging

The hash is the identity. Re-uploading identical bytes deduplicates the body
and appends provenance. Writes are atomic (temp file + fsync + rename), and
reads verify the hash before returning data.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from huntress_contracts import (
    ArtifactMetadata,
    ArtifactProvenance,
    ArtifactRef,
    RedactionStatus,
    canonical_json,
    sha256_hex,
    utc_now,
)


class ArtifactStoreError(Exception):
    """Base artifact-store error."""


class ArtifactNotFound(ArtifactStoreError):
    """The requested artifact is not present."""


class ArtifactIntegrityError(ArtifactStoreError):
    """Stored bytes do not match their content hash."""


class ArtifactTooLarge(ArtifactStoreError):
    """The artifact exceeds the configured cap."""


class ArtifactStore:
    """Filesystem-backed content-addressed store with provenance sidecars."""

    def __init__(self, root: Path, *, max_artifact_bytes: int = 10 * 1024 * 1024) -> None:
        self.root = Path(root).expanduser().resolve()
        self.max_artifact_bytes = max_artifact_bytes
        self.objects = self.root / "objects"
        self.tmp = self.root / "tmp"
        self.objects.mkdir(parents=True, exist_ok=True)
        self.tmp.mkdir(parents=True, exist_ok=True)

    def _path(self, sha256: str) -> Path:
        if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
            raise ValueError(f"invalid artifact hash: {sha256!r}")
        return self.objects / sha256[:2] / sha256[2:4] / sha256

    def _meta_path(self, sha256: str) -> Path:
        return self._path(sha256).with_suffix(".json")

    def _atomic_write(self, target: Path, data: bytes, mode: int = 0o600) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=self.tmp, prefix="artifact-")
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            tmp_path.chmod(mode)
            tmp_path.replace(target)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def put(
        self,
        data: bytes,
        *,
        media_type: str,
        provenance: ArtifactProvenance,
        redaction_status: RedactionStatus | None = None,
        parent_refs: tuple[str, ...] = (),
    ) -> ArtifactRef:
        if len(data) > self.max_artifact_bytes:
            raise ArtifactTooLarge(
                f"artifact is {len(data)} bytes; cap is {self.max_artifact_bytes}"
            )
        digest = sha256_hex(data)
        path = self._path(digest)
        meta_path = self._meta_path(digest)
        status = redaction_status or provenance.redaction_status
        enriched = provenance.model_copy(
            update={
                "storage_key": digest,
                "media_type": media_type,
                "size_bytes": len(data),
                "redaction_status": status,
                "parent_refs": tuple(parent_refs),
            }
        )

        if path.exists():
            metadata = self.metadata(digest)
            existing = {canonical_json(p) for p in metadata.provenance}
            provenance_entries = list(metadata.provenance)
            if canonical_json(enriched) not in existing:
                provenance_entries.append(enriched)
            metadata = metadata.model_copy(
                update={"provenance": tuple(provenance_entries[-100:])}
            )
            self._atomic_write(
                meta_path,
                json.dumps(metadata.model_dump(mode="json"), indent=2, sort_keys=True).encode(),
                0o600,
            )
            return metadata.ref

        self._atomic_write(path, data)
        now = utc_now()
        ref = ArtifactRef(
            sha256=digest,
            media_type=media_type,
            size_bytes=len(data),
            created_at=now,
            redaction_status=status,
            parent_refs=tuple(parent_refs),
        )
        metadata = ArtifactMetadata(ref=ref, provenance=(enriched,), storage_key=digest)
        self._atomic_write(
            meta_path,
            json.dumps(metadata.model_dump(mode="json"), indent=2, sort_keys=True).encode(),
            0o600,
        )
        return ref

    def put_text(
        self,
        text: str,
        *,
        media_type: str = "text/plain; charset=utf-8",
        provenance: ArtifactProvenance,
        redaction_status: RedactionStatus | None = None,
        parent_refs: tuple[str, ...] = (),
    ) -> ArtifactRef:
        return self.put(
            text.encode("utf-8"),
            media_type=media_type,
            provenance=provenance,
            redaction_status=redaction_status,
            parent_refs=parent_refs,
        )

    def get(self, ref: str | ArtifactRef) -> bytes:
        digest = ref.sha256 if isinstance(ref, ArtifactRef) else ref
        path = self._path(digest)
        if not path.exists():
            raise ArtifactNotFound(digest)
        data = path.read_bytes()
        if sha256_hex(data) != digest:
            raise ArtifactIntegrityError(f"artifact {digest} failed integrity verification")
        return data

    def get_text(self, ref: str | ArtifactRef, *, encoding: str = "utf-8") -> str:
        return self.get(ref).decode(encoding, errors="replace")

    def exists(self, ref: str | ArtifactRef) -> bool:
        digest = ref.sha256 if isinstance(ref, ArtifactRef) else ref
        return self._path(digest).exists()

    def verify(self, ref: str | ArtifactRef) -> bool:
        try:
            self.get(ref)
        except ArtifactStoreError:
            return False
        return True

    def metadata(self, ref: str | ArtifactRef) -> ArtifactMetadata:
        digest = ref.sha256 if isinstance(ref, ArtifactRef) else ref
        meta_path = self._meta_path(digest)
        if not meta_path.exists():
            raise ArtifactNotFound(f"metadata for {digest} not found")
        try:
            return ArtifactMetadata.model_validate_json(meta_path.read_text())
        except Exception as exc:
            raise ArtifactIntegrityError(f"invalid metadata for {digest}: {exc}") from exc

    def list_metadata(self) -> Iterator[ArtifactMetadata]:
        for meta_path in sorted(self.objects.glob("*/*/*.json")):
            try:
                yield ArtifactMetadata.model_validate_json(meta_path.read_text())
            except Exception:  # noqa: S112 - skip corrupt sidecars during inventory
                continue

    def stats(self) -> dict[str, int]:
        artifacts = 0
        bytes_total = 0
        for meta in self.list_metadata():
            artifacts += 1
            bytes_total += meta.ref.size_bytes
        return {"artifacts": artifacts, "bytes": bytes_total}

    def export_tree(self, destination: Path) -> Path:
        """Copy the store for backup. Never used in the request path."""

        destination = Path(destination)
        if destination.exists():
            shutil.rmtree(destination)
        shutil.copytree(self.root, destination)
        return destination


def artifact_provenance(
    *,
    source_tool: str,
    tool_version: str = "unknown",
    engagement_id: str | None = None,
    target_id: str | None = None,
    asset_id: str | None = None,
    profile_id: str | None = None,
    action_request_id: str | None = None,
    policy_version: str | None = None,
    scope_hash: str | None = None,
    exit_status: int | None = None,
    redaction_status: RedactionStatus = RedactionStatus.RAW,
    parent_refs: tuple[str, ...] = (),
    note: str = "",
    now: datetime | None = None,
) -> ArtifactProvenance:
    """Construct provenance with one timestamp for a whole capture."""

    return ArtifactProvenance(
        engagement_id=engagement_id,
        target_id=target_id,
        asset_id=asset_id,
        acquisition_time=now or utc_now(),
        source_tool=source_tool,
        tool_version=tool_version,
        profile_id=profile_id,
        action_request_id=action_request_id,
        policy_version=policy_version,
        scope_hash=scope_hash,
        exit_status=exit_status,
        redaction_status=redaction_status,
        parent_refs=parent_refs,
        note=note,
    )
