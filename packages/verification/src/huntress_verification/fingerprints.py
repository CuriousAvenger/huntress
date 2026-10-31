"""Stable deduplication fingerprints for candidate findings."""

from __future__ import annotations

from collections.abc import Iterable

from huntress_contracts import ToolFinding, sha256_hex


def evidence_tokens(findings: Iterable[ToolFinding]) -> tuple[str, ...]:
    """Return stable evidence tokens, preferring parser fingerprints."""

    tokens: set[str] = set()
    for finding in findings:
        if finding.evidence_fingerprint:
            tokens.add(f"fp:{finding.evidence_fingerprint}")
        for ref in finding.artifact_refs:
            tokens.add(f"art:{ref}")
        tokens.add(
            f"type:{finding.finding_type}|profile:{finding.tool_profile_id}|"
            f"bug:{finding.bug_class_id or ''}"
        )
    return tuple(sorted(tokens))


def finding_fingerprint(
    *,
    engagement_id: str,
    target_id: str,
    bug_class_id: str,
    findings: Iterable[ToolFinding],
) -> str:
    """Fingerprint the asset, issue class, and deterministic evidence identity."""

    tokens = evidence_tokens(findings)
    material = "|".join((engagement_id, target_id, bug_class_id, *tokens))
    return sha256_hex(material)


def similarity(left: Iterable[str], right: Iterable[str]) -> float:
    """Jaccard similarity over evidence tokens."""

    left_set = set(left)
    right_set = set(right)
    if not left_set and not right_set:
        return 0.0
    union = left_set | right_set
    return len(left_set & right_set) / len(union)
