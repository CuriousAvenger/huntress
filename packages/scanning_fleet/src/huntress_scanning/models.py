"""Internal scanning models shared by HTTP/DNS handlers and parsers."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime

from huntress_contracts import FindingConfidence, HttpMethod, OracleArchetype


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """A bounded, raw HTTP response captured by the scanning fleet."""

    url: str
    method: HttpMethod
    status_code: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    elapsed_ms: int
    truncated: bool = False
    request_headers: tuple[tuple[str, str], ...] = ()

    def header(self, name: str) -> str | None:
        wanted = name.lower()
        for key, value in self.headers:
            if key.lower() == wanted:
                return value
        return None

    def header_values(self, name: str) -> tuple[str, ...]:
        wanted = name.lower()
        return tuple(value for key, value in self.headers if key.lower() == wanted)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def media_type(self) -> str:
        content_type = self.header("content-type") or "application/octet-stream"
        return content_type.split(";", 1)[0].strip().lower() or "application/octet-stream"


@dataclass(frozen=True, slots=True)
class FindingSpec:
    """Parser output before IDs and provenance are attached."""

    finding_type: str
    title: str
    confidence: FindingConfidence
    artifact_refs: tuple[str, ...]
    bug_class_id: str | None = None
    cwe_ids: tuple[int, ...] = ()
    oracle_hint: OracleArchetype | None = None
    excerpt: str = ""
    details: Mapping[str, str | int | float | bool] = field(default_factory=dict)
    evidence_fingerprint: str = ""
    signature_ref: str | None = None


@dataclass(frozen=True, slots=True)
class ScanObservation:
    """Raw observation returned by a handler before finding materialization."""

    findings: tuple[FindingSpec, ...] = ()
    artifact_refs: tuple[str, ...] = ()
    request_count: int = 0
    output_truncated: bool = False
    notes: str = ""
    observed_at: datetime | None = None


class ScanError(Exception):
    """Base error for a bounded scan."""


class ScanAuthorizationError(ScanError):
    """A per-request scope re-check denied a URL."""


class ScanTimeout(ScanError):
    """The target did not respond within the profile deadline."""


class ScanRequestError(ScanError):
    """The request failed before a usable response was captured."""
