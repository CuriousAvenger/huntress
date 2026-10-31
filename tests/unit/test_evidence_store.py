"""Content-addressed artifact storage, provenance, and redaction."""

from __future__ import annotations

from pathlib import Path

import pytest
from huntress_contracts import RedactionStatus, sha256_hex, utc_now
from huntress_evidence import (
    ArtifactIntegrityError,
    ArtifactNotFound,
    ArtifactStore,
    ArtifactTooLarge,
    artifact_provenance,
    contains_high_confidence_secret,
    redact_headers,
    redact_text,
)


def _provenance(engagement_id: str = "eng_pytest000001"):
    return artifact_provenance(
        source_tool="pytest",
        tool_version="1.0",
        engagement_id=engagement_id,
        target_id="tgt_pytest000001",
        profile_id="http.baseline",
        now=utc_now(),
    )


def test_put_get_and_deduplicate(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    first = store.put_text("hello", provenance=_provenance(), media_type="text/plain")
    second = store.put_text("hello", provenance=_provenance(), media_type="text/plain")

    assert first.sha256 == sha256_hex("hello")
    assert first.sha256 == second.sha256
    assert store.get(first) == b"hello"
    assert store.get_text(first) == "hello"
    assert store.exists(first)
    assert store.verify(first)
    assert store.stats()["artifacts"] == 1

    metadata = store.metadata(first)
    assert metadata.ref.sha256 == first.sha256
    assert len(metadata.provenance) == 2
    assert metadata.provenance[0].engagement_id == "eng_pytest000001"


def test_put_text_accepts_redaction_and_parent_refs(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    parent = store.put_text("raw", provenance=_provenance())
    child = store.put_text(
        "sanitized",
        provenance=_provenance(),
        redaction_status=RedactionStatus.REDACTED,
        parent_refs=(parent.sha256,),
    )
    assert child.redaction_status is RedactionStatus.REDACTED
    assert child.parent_refs == (parent.sha256,)
    assert store.metadata(child).ref.redaction_status is RedactionStatus.REDACTED


def test_missing_and_tampered_artifacts_are_detected(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    ref = store.put_text("original", provenance=_provenance())
    with pytest.raises(ArtifactNotFound):
        store.get("0" * 64)

    path = store.objects / ref.sha256[:2] / ref.sha256[2:4] / ref.sha256
    path.write_bytes(b"tampered")
    with pytest.raises(ArtifactIntegrityError):
        store.get(ref)
    assert not store.verify(ref)


def test_artifact_size_cap_is_enforced(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "artifacts", max_artifact_bytes=4)
    with pytest.raises(ArtifactTooLarge):
        store.put(b"12345", media_type="text/plain", provenance=_provenance())


def test_invalid_hash_is_rejected(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    with pytest.raises(ValueError, match="invalid artifact hash"):
        store.get("not-a-hash")
    with pytest.raises(ValueError, match="invalid artifact hash"):
        store.get("../escape")


def test_export_tree_copies_store(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    ref = store.put_text("copy me", provenance=_provenance())
    destination = store.export_tree(tmp_path / "backup")
    copied = ArtifactStore(destination)
    assert copied.get_text(ref) == "copy me"


def test_redaction_covers_high_confidence_secrets() -> None:
    secret = (
        "password = supersecret123\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "Authorization: Bearer abcdefghijklmnop\n"
        "github=ghp_" + "a" * 36 + "\n"
    )
    result = redact_text(secret)
    assert result.changed
    assert "supersecret123" not in result.text
    assert "AKIAIOSFODNN7EXAMPLE" not in result.text
    assert "abcdefghijklmnop" not in result.text
    assert "ghp_" not in result.text
    assert "password" in result.text.lower()
    assert contains_high_confidence_secret(secret)
    assert not contains_high_confidence_secret("nothing sensitive here")


def test_redact_headers_preserves_names_only() -> None:
    headers = redact_headers(
        {
            "Authorization": "Bearer secret-token",
            "Cookie": "session=abc",
            "Content-Type": "text/html",
        }
    )
    assert headers["Authorization"] == "[REDACTED:header]"
    assert headers["Cookie"] == "[REDACTED:header]"
    assert headers["Content-Type"] == "text/html"


def test_redaction_is_idempotent() -> None:
    once = redact_text("password = hunter2hunter2").text
    twice = redact_text(once).text
    assert once == twice
