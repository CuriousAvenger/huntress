"""Replay/fake-backend integration tests.

No test in this module opens a live target, Docker container, or model
connection. The fake backend is selected explicitly, and the restart test
reopens the same SQLite database and artifact store.
"""

from __future__ import annotations

import json
from pathlib import Path

from huntress_contracts import ApprovalStatus, RiskClass
from huntress_execution import (
    DEFAULT_PROFILE_REGISTRY,
    build_command,
    resolve_argv,
)
from huntress_orchestrator.cli import app
from huntress_orchestrator.config import Settings
from huntress_orchestrator.container import Container
from huntress_orchestrator.controller import Controller
from tests.conftest import ACTIVE_PROFILES, LOW_RISK_PROFILES, setup_engagement
from tests.helpers import make_target
from typer.testing import CliRunner

KEY = b"k" * 32


def test_exegol_profile_uses_the_fake_backend_when_explicitly_configured(
    controller: Controller,
) -> None:
    engagement_id, target_id = setup_engagement(
        controller,
        url="http://127.0.0.1:8080",
        profiles=(*LOW_RISK_PROFILES, "exegol.curl_headers"),
        preapproved=LOW_RISK_PROFILES,
    )
    plan = controller.request_action(
        engagement_id=engagement_id,
        profile_id="exegol.curl_headers",
        target_id=target_id,
    )
    assert plan.approval_request is not None
    assert not plan.executed

    outcome = controller.approve_action(
        plan.approval_request.approval_id,
        approved_by="Reviewer One",
        note="pytest fake Exegol approval",
    )
    assert outcome.outcome is not None
    assert outcome.outcome.backend == "fake"
    assert outcome.outcome.run_result.status.value == "succeeded"
    assert outcome.outcome.attempt.profile_id == "exegol.curl_headers"
    assert outcome.outcome.attempt.artifact_refs

    # The fake backend never contacts Exegol; the durable attempt is enough to
    # prove the profile and authorization path were selected.
    attempts = controller.container.repos.attempts.list_by_engagement(engagement_id)
    assert len(attempts) == 1
    assert attempts[0].idempotency_key == plan.request.idempotency_key


def test_profile_argv_resolution_is_fixed_and_shell_quoted() -> None:
    target = make_target(
        "eng_argv000000001",
        "http://127.0.0.1:8080",
        target_id="tgt_argv000000001",
    )
    profile = DEFAULT_PROFILE_REGISTRY.require("exegol.curl_headers")
    argv = resolve_argv(profile, target)
    command = build_command(profile, target)
    assert argv[0] == "curl"
    assert argv[-1] == target.base_url
    assert command.startswith("curl ")
    assert target.base_url in command
    assert "{base_url}" not in command
    assert ";" not in command


def test_pending_approval_survives_a_process_restart(settings: Settings) -> None:
    first = Container(settings)
    try:
        controller = Controller(first)
        engagement_id, target_id = setup_engagement(
            controller,
            url="http://127.0.0.1:8080",
            profiles=(*LOW_RISK_PROFILES, *ACTIVE_PROFILES),
            preapproved=LOW_RISK_PROFILES,
            max_risk=RiskClass.ACTIVE,
        )
        plan = controller.request_action(
            engagement_id=engagement_id,
            profile_id="http.open_redirect",
            target_id=target_id,
        )
        assert plan.approval_request is not None
        approval_id = plan.approval_request.approval_id
        assert controller.get_engagement(engagement_id).state.value == "WAITING_FOR_APPROVAL"
    finally:
        first.close()

    second = Container(settings)
    try:
        controller = Controller(second)
        pending = controller.pending_approvals(engagement_id)
        assert [item.approval_id for item in pending] == [approval_id]
        approval = second.repos.approvals.get_request(approval_id)
        assert approval is not None
        assert approval.status is ApprovalStatus.PENDING

        outcome = controller.approve_action(
            approval_id,
            approved_by="Reviewer One",
            note="approved after restart",
        )
        assert outcome.outcome is not None
        assert outcome.outcome.backend == "fake"
        assert controller.get_engagement(engagement_id).state.value == "ANALYSIS"
    finally:
        second.close()


def test_cli_round_trip_uses_environment_configuration(tmp_path: Path) -> None:
    runner = CliRunner()
    data_dir = tmp_path / "cli-data"
    env = {
        "HUNTRESS_DATA_DIR": str(data_dir),
        "HUNTRESS_MODE": "lab",
        "HUNTRESS_EXEGOL_BACKEND": "fake",
        "HUNTRESS_OPERATOR": "cli-tester",
    }

    result = runner.invoke(app, ["--json", "init"], env=env)
    assert result.exit_code == 0, result.output
    health = json.loads(result.stdout)
    assert health["backend_mode"] == "fake"

    result = runner.invoke(
        app,
        ["--json", "engagement", "create", "--name", "cli round trip"],
        env=env,
    )
    assert result.exit_code == 0, result.output
    engagement_id = json.loads(result.stdout)["engagement_id"]

    result = runner.invoke(
        app,
        [
            "--json",
            "scope",
            "set",
            engagement_id,
            "--asset",
            "http://127.0.0.1:1",
            "--authorization-ref",
            "pytest CLI authorization",
            "--approved-by",
            "Reviewer One",
        ],
        env=env,
    )
    assert result.exit_code == 0, result.output
    scope = json.loads(result.stdout)
    assert scope["approved_by"] == "Reviewer One"

    result = runner.invoke(app, ["--json", "target", "sync", engagement_id], env=env)
    assert result.exit_code == 0, result.output
    targets = json.loads(result.stdout)
    assert len(targets) == 1

    result = runner.invoke(
        app,
        ["--json", "scan", engagement_id, "--profile", "http.baseline"],
        env=env,
    )
    assert result.exit_code == 0, result.output
    plan = json.loads(result.stdout)
    assert plan["outcome"]["backend"] == "fake"

    result = runner.invoke(app, ["--json", "audit", "verify"], env=env)
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["valid"] is True

