"""HMAC sealing, signing, and constant-time verification.

The signing key is local authority. It is never exposed to the model, the
scanner container, or a report. Losing it invalidates existing seals; rotating
it requires re-approving scopes and approvals.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path

from huntress_contracts import ApprovalRecord, ScopeDocument, canonical_json, model_self_hash

_HASH_EXCLUDES = frozenset({"content_hash", "signature"})


def load_or_create_signing_key(path: Path) -> bytes:
    """Load a 32-byte key, creating it atomically with mode 0600 if absent."""

    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        existing = path.read_bytes().strip()
    except FileNotFoundError:
        existing = b""
    if existing:
        if len(existing) < 32:
            raise ValueError(f"signing key at {path} is shorter than 32 bytes")
        return existing

    key = secrets.token_hex(32).encode("ascii")
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(key)
            handle.flush()
            os.fsync(handle.fileno())
        tmp.replace(path)
    finally:
        if tmp.exists():
            tmp.unlink()
    return key


def sign(key: bytes, message: str) -> str:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_signature(key: bytes, message: str, signature: str) -> bool:
    if not signature:
        return False
    expected = sign(key, message)
    return hmac.compare_digest(expected, signature)


def scope_content_hash(scope: ScopeDocument) -> str:
    """Recompute the hash from the document, excluding its own hash/signature."""

    return model_self_hash(scope, exclude=_HASH_EXCLUDES)


def verify_scope_seal(scope: ScopeDocument, key: bytes) -> bool:
    digest = scope_content_hash(scope)
    if not hmac.compare_digest(digest, scope.content_hash):
        return False
    return verify_signature(key, digest, scope.signature)


def approval_content_hash(record: ApprovalRecord) -> str:
    return model_self_hash(record, exclude=_HASH_EXCLUDES)


def verify_approval_seal(record: ApprovalRecord, key: bytes) -> bool:
    digest = approval_content_hash(record)
    if not hmac.compare_digest(digest, record.content_hash):
        return False
    return verify_signature(key, digest, record.signature)


def decision_content_hash(decision: object) -> str:
    """Hash a policy decision for the audit trail."""

    from huntress_contracts import PolicyDecision

    if not isinstance(decision, PolicyDecision):  # pragma: no cover - defensive
        raise TypeError("decision_content_hash expects PolicyDecision")
    return model_self_hash(decision, exclude=frozenset({"decision_hash"}))


def stable_digest(value: object) -> str:
    """Hash arbitrary JSON-serializable data deterministically."""

    import hashlib

    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
