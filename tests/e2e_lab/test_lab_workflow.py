"""Isolated end-to-end lab tests.

The lab is a deliberately vulnerable loopback server. These tests use the real
builtin HTTP scanner, the real deterministic validation pipeline, SQLite, and
the content-addressed artifact store. They never use a live target, Docker, or
a model provider.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from huntress_contracts import (
    ExecutionBackend,
    GateName,
    GateStatus,
    HumanReviewStatus,
    RiskClass,
    SeverityBand,
    ValidationStatus,
)
from huntress_orchestrator.config import Settings
from huntress_orchestrator.container import Container
from huntress_orchestrator.controller import Controller
from huntress_orchestrator.lab import LabServer
from tests.conftest import ACTIVE_PROFILES, LOW_RISK_PROFILES, setup_engagement

pytestmark = pytest.mark.lab


@pytest.fixture
def lab_container(settings: Settings) -> Iterator[Container]:
    instance = Container(settings.model_copy(update={"exegol_backend": ExecutionBackend.AUTO}))
    try:
        yield instance
    finally:
        instance.close()


@pytest.fixture
def lab_controller(lab_container: Container) -> Controller:
    return Controller(lab_container)


def _active_engagement(controller: Controller, lab: LabServer) -> tuple[str, str]:
    return setup_engagement(
        controller,
        url=lab.base_url,
        profiles=(*LOW_RISK_PROFILES, *ACTIVE_PROFILES),
        preapproved=LOW_RISK_PROFILES,
        max_risk=RiskClass.ACTIVE,
        name="lab active engagement",
    )


def _approved_scan(controller: Controller, *, engagement_id: str, target_id: str, profile: str):
    plan = controller.request_action(
        engagement_id=engagement_id,
        profile_id=profile,
        target_id=target_id,
    )
    assert plan.approval_request is not None
    outcome = controller.approve_action(
        plan.approval_request.approval_id,
        approved_by="Reviewer One",
        note=f"pytest approval for {profile}",
    )
    assert outcome.outcome is not None
    assert outcome.outcome.run_result.status.value == "succeeded"
    return outcome.outcome


def test_exposed_file_flows_through_validation_review_and_submission(
    lab: LabServer, lab_controller: Controller
) -> None:
    engagement_id, target_id = setup_engagement(
        lab_controller, url=lab.base_url, name="lab exposed files"
    )
    plan = lab_controller.request_action(
        engagement_id=engagement_id,
        profile_id="http.exposed_files",
        target_id=target_id,
    )
    assert plan.executed
    assert plan.outcome is not None

    env_finding = next(
        finding for finding in plan.outcome.findings if finding.finding_type == "http.env_exposure"
    )
    assert env_finding.bug_class_id == "bug_env_exposure"
    assert env_finding.artifact_refs
    assert all(lab_controller.container.store.exists(ref) for ref in env_finding.artifact_refs)

    validation = lab_controller.validate_finding(
        engagement_id=engagement_id,
        tool_finding_ids=[env_finding.finding_id],
        bug_class_id=env_finding.bug_class_id,
        title=env_finding.title,
        claim="The approved lab target served a dotenv file with credential-shaped assignments.",
        severity_band=SeverityBand.HIGH,
        impact_summary="Credential-shaped configuration was disclosed without authentication.",
    )
    assert validation.status is ValidationStatus.PASSED
    gates = {gate.gate: gate.status for gate in validation.finding.gates}
    assert all(status is GateStatus.PASS for status in gates.values())
    assert gates[GateName.TECHNICAL_ORACLE] is GateStatus.PASS

    review = lab_controller.review_finding(
        validation.finding.finding_id,
        reviewer="Reviewer One",
        decision=HumanReviewStatus.APPROVED,
        notes="Verified the preserved response and dotenv assignment.",
    )
    assert review.review.decision is HumanReviewStatus.APPROVED

    report = lab_controller.draft_report(
        engagement_id=engagement_id,
        destination="manual",
        title="Lab exposed configuration report",
    )
    assert report.finding_ids == (validation.finding.finding_id,)
    lab_controller.request_report_approval(report.report_id)
    approved = lab_controller.approve_report(
        report.report_id,
        approved_by="Reviewer One",
        destination="manual",
        note="Approved for local lab submission.",
    )
    assert approved.status.value == "approved"
    submitted = lab_controller.submit_report(report.report_id)
    assert submitted.status.value == "submitted"
    assert lab_controller.get_engagement(engagement_id).state.value == "CLOSED"
    assert lab_controller.audit_verify(engagement_id).valid


def test_differential_sqli_passes_in_a_fresh_engagement(
    lab: LabServer, lab_controller: Controller
) -> None:
    engagement_id, target_id = _active_engagement(lab_controller, lab)
    outcome = _approved_scan(
        lab_controller,
        engagement_id=engagement_id,
        target_id=target_id,
        profile="http.error_based_sqli",
    )
    finding = next(
        item for item in outcome.findings if item.finding_type == "http.error_based_sqli"
    )
    assert finding.details["repetitions"] == 3
    assert "SQL syntax" in str(finding.details["signature"])

    validation = lab_controller.validate_finding(
        engagement_id=engagement_id,
        tool_finding_ids=[finding.finding_id],
        bug_class_id=finding.bug_class_id,
        title=finding.title,
        claim="Three independent quote probes produced the same database error absent from baseline.",
        severity_band=SeverityBand.HIGH,
        impact_summary="Database error details are disclosed and input is not safely parameterized.",
    )
    assert validation.status is ValidationStatus.PASSED
    gates = {gate.gate: gate.status for gate in validation.finding.gates}
    assert gates[GateName.REPRODUCIBILITY] is GateStatus.PASS
    assert gates[GateName.TECHNICAL_ORACLE] is GateStatus.PASS
    assert validation.finding.reproduction.performed_repetitions == 3


def test_open_redirect_and_reflection_are_scoped_observations(
    lab: LabServer, lab_controller: Controller
) -> None:
    redirect_engagement, redirect_target = _active_engagement(lab_controller, lab)
    redirect_outcome = _approved_scan(
        lab_controller,
        engagement_id=redirect_engagement,
        target_id=redirect_target,
        profile="http.open_redirect",
    )
    redirect_finding = next(
        item for item in redirect_outcome.findings if item.finding_type == "http.open_redirect"
    )
    assert "huntress-canary.invalid" in str(redirect_finding.details["location"])
    redirect_validation = lab_controller.validate_finding(
        engagement_id=redirect_engagement,
        tool_finding_ids=[redirect_finding.finding_id],
        bug_class_id=redirect_finding.bug_class_id,
        title=redirect_finding.title,
        claim="The next parameter redirected to the tester-controlled canary host.",
        severity_band=SeverityBand.MEDIUM,
        impact_summary="A user-controlled parameter controls the Location header.",
    )
    assert redirect_validation.status is ValidationStatus.PASSED

    reflection_engagement, reflection_target = _active_engagement(lab_controller, lab)
    reflection_outcome = _approved_scan(
        lab_controller,
        engagement_id=reflection_engagement,
        target_id=reflection_target,
        profile="http.reflected_marker",
    )
    reflection_finding = next(
        item
        for item in reflection_outcome.findings
        if item.finding_type == "http.reflected_html_marker"
    )
    assert reflection_finding.details["context"] == "html_raw"
    reflection_validation = lab_controller.validate_finding(
        engagement_id=reflection_engagement,
        tool_finding_ids=[reflection_finding.finding_id],
        bug_class_id=reflection_finding.bug_class_id,
        title=reflection_finding.title,
        claim="A unique inert marker was reflected unescaped in the raw HTML body.",
        severity_band=SeverityBand.MEDIUM,
        impact_summary="Unescaped reflection provides the precondition for script injection.",
    )
    assert reflection_validation.status is ValidationStatus.PASSED
    assert (
        next(
            gate
            for gate in reflection_validation.finding.gates
            if gate.gate is GateName.TECHNICAL_ORACLE
        ).status
        is GateStatus.PASS
    )


def test_audit_chain_detects_tampering(
    lab: LabServer, lab_controller: Controller
) -> None:
    engagement_id, target_id = setup_engagement(
        lab_controller, url=lab.base_url, name="lab audit chain"
    )
    lab_controller.request_action(
        engagement_id=engagement_id,
        profile_id="http.baseline",
        target_id=target_id,
    )
    assert lab_controller.audit_verify(engagement_id).valid

    # The repository is append-only by API, so tamper directly with SQLite to
    # prove verification is not merely checking that rows exist.
    with lab_controller.container.database.transaction() as connection:
        connection.execute(
            "UPDATE audit_events SET record_json = json_set(record_json, '$.outcome', 'forged') "
            "WHERE event_id = (SELECT event_id FROM audit_events WHERE engagement_id = ? "
            "ORDER BY rowid LIMIT 1)",
            (engagement_id,),
        )

    verification = lab_controller.audit_verify(engagement_id)
    assert not verification.valid
    assert verification.reason
