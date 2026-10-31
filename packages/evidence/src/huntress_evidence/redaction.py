"""Conservative secret redaction for retained artifacts and report text.

Redaction is best-effort defence in depth, not a guarantee. Raw evidence is
retained separately under access control; sanitized derivatives point back to
their parent artifacts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----.*?"
            r"-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[REDACTED:private_key]",
    ),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED:aws_access_key]"),
    (
        "github_token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
        "[REDACTED:github_token]",
    ),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED:slack_token]"),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        "[REDACTED:jwt]",
    ),
    (
        "authorization_header",
        re.compile(r"(?i)\b(authorization\s*:\s*)(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"),
        r"\1\2 [REDACTED:authorization]",
    ),
    (
        "secret_assignment",
        re.compile(
            r"(?i)\b(password|passwd|secret|client_secret|api[_-]?key|access[_-]?token|"
            r"refresh[_-]?token|auth[_-]?token)\b(\s*[:=]\s*)([\"']?)([^\s\"'<>]{6,})\3"
        ),
        r"\1\2\3[REDACTED:secret]\3",
    ),
)

_SECRET_KEY_HEADER = re.compile(
    r"(?i)^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token)$"
)


@dataclass(frozen=True, slots=True)
class RedactionResult:
    text: str
    redacted_count: int
    categories: tuple[str, ...]

    @property
    def changed(self) -> bool:
        return self.redacted_count > 0


def redact_text(text: str) -> RedactionResult:
    """Redact high-confidence credential patterns and count replacements."""

    categories: list[str] = []
    total = 0
    result = text
    for category, pattern, replacement in _PATTERNS:
        result, count = pattern.subn(replacement, result)
        if count:
            categories.append(category)
            total += count
    return RedactionResult(result, total, tuple(sorted(set(categories))))


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Replace sensitive header values while preserving header names."""

    redacted: dict[str, str] = {}
    for name, value in headers.items():
        redacted[name] = "[REDACTED:header]" if _SECRET_KEY_HEADER.match(name.strip()) else value
    return redacted


def contains_high_confidence_secret(text: str) -> bool:
    """Used by the env-exposure oracle to avoid treating every KEY=value as a secret."""

    return redact_text(text).changed
