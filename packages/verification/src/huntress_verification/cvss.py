"""Deterministic CVSS 3.1 base-score calculation.

Only base metrics are accepted. Temporal and environmental metrics are not
invented from evidence; if they matter, the caller must provide a complete
vector and the finding retains the uncertainty separately.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from huntress_contracts import SeverityBand, band_for_cvss

_METRIC_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

_WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}

_PR_WEIGHTS: dict[str, dict[str, float]] = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},
}


@dataclass(frozen=True, slots=True)
class CvssScore:
    vector: str
    score: float
    band: SeverityBand
    metrics: dict[str, str]


def _roundup(value: float) -> float:
    """CVSS 3.1 Roundup: smallest one-decimal number >= value."""

    return math.ceil(round(value * 10, 6)) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    """Parse a CVSS 3.1 base vector into a metric mapping."""

    if not vector or len(vector) > 200:
        raise ValueError("CVSS vector is empty or too long")
    parts = vector.split("/")
    if not parts or parts[0] != "CVSS:3.1":
        raise ValueError("only CVSS:3.1 base vectors are supported")
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if ":" not in part:
            raise ValueError(f"invalid CVSS metric: {part!r}")
        key, value = part.split(":", 1)
        if key not in _METRIC_ORDER:
            raise ValueError(f"unsupported CVSS metric: {key}")
        if key in metrics:
            raise ValueError(f"duplicate CVSS metric: {key}")
        if key == "PR":
            if value not in {"N", "L", "H"}:
                raise ValueError(f"invalid value {value!r} for CVSS metric PR")
            metrics[key] = value
            continue
        if key == "S":
            if value not in _PR_WEIGHTS:
                raise ValueError(f"invalid value {value!r} for CVSS metric S")
            metrics[key] = value
            continue
        if value not in _WEIGHTS[key]:
            raise ValueError(f"invalid value {value!r} for CVSS metric {key}")
        metrics[key] = value
    if set(metrics) != set(_METRIC_ORDER):
        missing = sorted(set(_METRIC_ORDER) - set(metrics))
        raise ValueError(f"missing CVSS metrics: {missing}")
    if metrics["PR"] not in _PR_WEIGHTS[metrics["S"]]:
        raise ValueError("invalid CVSS PR value for the selected scope")
    return metrics


def score_vector(vector: str) -> CvssScore:
    """Compute the CVSS 3.1 base score and qualitative band."""

    metrics = parse_vector(vector)
    scope = metrics["S"]
    av = _WEIGHTS["AV"][metrics["AV"]]
    ac = _WEIGHTS["AC"][metrics["AC"]]
    pr = _PR_WEIGHTS[scope][metrics["PR"]]
    ui = _WEIGHTS["UI"][metrics["UI"]]
    confidentiality = _WEIGHTS["C"][metrics["C"]]
    integrity = _WEIGHTS["I"][metrics["I"]]
    availability = _WEIGHTS["A"][metrics["A"]]

    iss = 1.0 - (1.0 - confidentiality) * (1.0 - integrity) * (1.0 - availability)
    impact = 6.42 * iss if scope == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0.0:
        raw = 0.0
    elif scope == "U":
        raw = min(impact + exploitability, 10.0)
    else:
        raw = min(1.08 * (impact + exploitability), 10.0)
    score = _roundup(raw)
    return CvssScore(
        vector=f"CVSS:3.1/{'/'.join(f'{key}:{metrics[key]}' for key in _METRIC_ORDER)}",
        score=score,
        band=band_for_cvss(score),
        metrics=metrics,
    )
