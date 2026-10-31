"""Deterministic severity assessment from documented inputs."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from huntress_contracts import (
    BugClass,
    GateStatus,
    SeverityAssessment,
    SeverityBand,
    band_for_cvss,
)

from .cvss import score_vector

_HINT_BANDS: dict[str, SeverityBand] = {
    "critical": SeverityBand.CRITICAL,
    "high": SeverityBand.HIGH,
    "medium": SeverityBand.MEDIUM,
    "low": SeverityBand.LOW,
    "info": SeverityBand.INFO,
    "informational": SeverityBand.INFO,
    "unknown": SeverityBand.UNKNOWN,
}


@dataclass(frozen=True, slots=True)
class SeverityInputs:
    """Operator/parser supplied scoring inputs. No model prose is accepted."""

    impact_summary: str
    cvss_vector: str | None = None
    band: SeverityBand | None = None
    exploitability_summary: str = ""
    uncertainty: str = ""
    scoring_inputs: Mapping[str, str | int | float | bool] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SeverityOutcome:
    assessment: SeverityAssessment
    gate_status: GateStatus
    reason: str


class SeverityAssessor:
    """Compute CVSS 3.1 or accept an explicit qualitative band.

    A bug-class default hint is recorded as uncertainty and is *not* enough to
    pass the severity gate. This keeps scanner hints from becoming proof.
    """

    def assess(
        self,
        *,
        bug_class: BugClass,
        inputs: SeverityInputs | None,
    ) -> SeverityOutcome:
        if inputs is not None and inputs.cvss_vector:
            try:
                scored = score_vector(inputs.cvss_vector)
            except ValueError as exc:
                assessment = SeverityAssessment(
                    band=SeverityBand.UNKNOWN,
                    method="qualitative",
                    impact_summary=inputs.impact_summary or "CVSS vector could not be scored.",
                    uncertainty=str(exc)[:2000],
                    scoring_inputs=dict(inputs.scoring_inputs),
                )
                return SeverityOutcome(
                    assessment=assessment,
                    gate_status=GateStatus.FAIL,
                    reason=f"invalid CVSS 3.1 vector: {exc}",
                )
            if inputs.band is not None and inputs.band is not scored.band:
                return SeverityOutcome(
                    assessment=SeverityAssessment(
                        band=inputs.band,
                        method="qualitative",
                        impact_summary=inputs.impact_summary or bug_class.name,
                        exploitability_summary=inputs.exploitability_summary,
                        uncertainty=(
                            f"explicit band {inputs.band.value} conflicts with CVSS "
                            f"{scored.score} ({scored.band.value})"
                        )[:2000],
                        scoring_inputs=dict(inputs.scoring_inputs),
                    ),
                    gate_status=GateStatus.FAIL,
                    reason="explicit severity band conflicts with the CVSS score",
                )
            assessment = SeverityAssessment(
                band=scored.band,
                method="cvss_v31",
                cvss_vector=scored.vector,
                cvss_score=scored.score,
                impact_summary=inputs.impact_summary or f"CVSS 3.1 base score {scored.score}.",
                exploitability_summary=inputs.exploitability_summary,
                uncertainty=inputs.uncertainty,
                scoring_inputs=dict(inputs.scoring_inputs),
            )
            return SeverityOutcome(
                assessment=assessment,
                gate_status=GateStatus.PASS,
                reason=f"CVSS 3.1 base score {scored.score} ({scored.band.value})",
            )

        if inputs is not None and inputs.band is not None and inputs.band is not SeverityBand.UNKNOWN:
            assessment = SeverityAssessment(
                band=inputs.band,
                method="qualitative",
                impact_summary=inputs.impact_summary or bug_class.name,
                exploitability_summary=inputs.exploitability_summary,
                uncertainty=inputs.uncertainty,
                scoring_inputs=dict(inputs.scoring_inputs),
            )
            return SeverityOutcome(
                assessment=assessment,
                gate_status=GateStatus.PASS,
                reason=f"explicit qualitative severity band {inputs.band.value}",
            )

        hint = _HINT_BANDS.get(bug_class.default_severity_hint.lower(), SeverityBand.UNKNOWN)
        uncertainty = (
            "Severity is derived from a bug-class hint, not demonstrated impact. "
            "Provide a CVSS 3.1 vector or an explicit qualitative band."
        )
        assessment = SeverityAssessment(
            band=hint,
            method="bug_class_hint",
            impact_summary=(
                inputs.impact_summary
                if inputs is not None and inputs.impact_summary
                else f"{bug_class.name}: no demonstrated impact recorded."
            ),
            exploitability_summary=inputs.exploitability_summary if inputs is not None else "",
            uncertainty=uncertainty,
            scoring_inputs={
                "bug_class_id": bug_class.bug_class_id,
                "cwe_id": bug_class.cwe_id,
                "default_severity_hint": bug_class.default_severity_hint,
                **dict(inputs.scoring_inputs if inputs is not None else {}),
            },
        )
        return SeverityOutcome(
            assessment=assessment,
            gate_status=GateStatus.INCONCLUSIVE,
            reason="severity is a bug-class hint, not demonstrated impact",
        )


def band_for_score(score: float) -> SeverityBand:
    return band_for_cvss(score)
