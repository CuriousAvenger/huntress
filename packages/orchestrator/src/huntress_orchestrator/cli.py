"""Operator CLI for the Huntress engagement controller.

The CLI is a thin, auditable adapter over ``Controller``. It never constructs
commands or URLs for the model, and it always requires a named human for
approval and report submission. Machine-readable output is available with the
global ``--json`` flag.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import fields, is_dataclass
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, NoReturn, cast

import typer
from huntress_contracts import (
    AssetConfidence,
    AssetKind,
    EngagementMode,
    HumanReviewStatus,
    RiskClass,
    ScopeAsset,
    ScopeDraft,
    ScopeStatus,
    SeverityBand,
    SideEffectClass,
    sha256_hex,
    utc_now,
)
from huntress_contracts.scope import AssetProvenance, ReportingRules, ROEConstraints, TestingWindow
from huntress_governance import HuntressError
from pydantic import BaseModel
from rich.console import Console
from rich.table import Table

from .config import load_settings
from .container import Container
from .controller import ActionPlan, Controller
from .lab import serve_lab

console = Console(stderr=False)
error_console = Console(stderr=True)

app = typer.Typer(
    name="huntress",
    help="Policy-enforced autonomous bug-bounty engine.",
    no_args_is_help=True,
    add_completion=False,
)
engagement_app = typer.Typer(help="Create and inspect engagements.", no_args_is_help=True)
scope_app = typer.Typer(help="Compile and inspect sealed scopes.", no_args_is_help=True)
target_app = typer.Typer(help="Register and inspect approved targets.", no_args_is_help=True)
approvals_app = typer.Typer(help="Review pending human approvals.", no_args_is_help=True)
findings_app = typer.Typer(help="Inspect tool and validated findings.", no_args_is_help=True)
report_app = typer.Typer(help="Draft, approve, and submit reports.", no_args_is_help=True)
audit_app = typer.Typer(help="Verify the append-only audit chain.", no_args_is_help=True)
lab_app = typer.Typer(help="Run the deterministic local lab target.", no_args_is_help=True)

app.add_typer(engagement_app, name="engagement")
app.add_typer(scope_app, name="scope")
app.add_typer(target_app, name="target")
app.add_typer(approvals_app, name="approvals")
app.add_typer(findings_app, name="findings")
app.add_typer(report_app, name="report")
app.add_typer(audit_app, name="audit")
app.add_typer(lab_app, name="lab")


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def _state(ctx: typer.Context) -> dict[str, Any]:
    if not isinstance(ctx.obj, dict):
        ctx.obj = {}
    return cast(dict[str, Any], ctx.obj)


@app.callback()
def _root(
    ctx: typer.Context,
    config: Path | None = typer.Option(
        None,
        "--config",
        envvar="HUNTRESS_CONFIG_FILE",
        help="TOML config file (default: config/defaults.toml).",
    ),
    as_json: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """Huntress: deterministic policy, durable evidence, human control."""

    _state(ctx).update({"config": config, "json": as_json})


@contextmanager
def _open(ctx: typer.Context) -> Iterator[Container]:
    settings = load_settings(config_file=_state(ctx).get("config"))
    container = Container(settings)
    try:
        yield container
    finally:
        container.close()


def _jsonable(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _jsonable(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(item) for item in value]
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (datetime, Path)):
        return str(value)
    return value


def _emit(ctx: typer.Context, value: object) -> None:
    if _state(ctx).get("json"):
        typer.echo(json.dumps(_jsonable(value), indent=2, sort_keys=True))


def _print(ctx: typer.Context, message: str) -> None:
    if not _state(ctx).get("json"):
        console.print(message)


def _fail(message: str, *, code: int = 1) -> NoReturn:
    error_console.print(f"[red]error:[/red] {message}")
    raise typer.Exit(code)


def _table(title: str, columns: Sequence[str], rows: Sequence[Sequence[object]]) -> None:
    table = Table(title=title, show_lines=False)
    for column in columns:
        table.add_column(column)
    for row in rows:
        table.add_row(*(str(cell) for cell in row))
    console.print(table)


def _engagement_id(container: Container, prefix: str | None) -> str:
    """Resolve a full engagement ID from a unique prefix."""

    if prefix is None:
        raise typer.BadParameter("an engagement ID is required")
    matches = [
        engagement.engagement_id
        for engagement in container.repos.engagements.list_all(limit=10_000)
        if engagement.engagement_id.startswith(prefix)
    ]
    if not matches:
        raise typer.BadParameter(f"no engagement matches {prefix!r}")
    if len(matches) > 1:
        raise typer.BadParameter(f"engagement prefix {prefix!r} is ambiguous")
    return matches[0]


def _profile_ids(container: Container) -> list[str]:
    return sorted(profile.profile_id for profile in container.profiles.all())


def _parse_asset(spec: str, *, now: datetime) -> ScopeAsset:
    raw = spec.strip()
    if not raw:
        raise typer.BadParameter("asset must not be empty")

    kind: AssetKind
    value = raw
    known = {item.value for item in AssetKind}
    if ":" in raw and raw.split(":", 1)[0] in known:
        kind_text, value = raw.split(":", 1)
        kind = AssetKind(kind_text)
    elif raw.startswith(("http://", "https://")):
        kind = AssetKind.URL
    else:
        try:
            ipaddress.IPv4Address(raw)
        except ValueError:
            kind = AssetKind.DOMAIN
        else:
            kind = AssetKind.IPV4

    asset_id = "asset_" + sha256_hex(f"{kind.value}|{value}")[:16]
    return ScopeAsset(
        asset_id=asset_id,
        kind=kind,
        value=value,
        provenance=AssetProvenance(
            source="operator",
            observed_at=now,
            confidence=AssetConfidence.CONFIRMED,
        ),
        policy_status=ScopeStatus.APPROVED,
    )


def _resolve_target(controller: Controller, engagement_id: str, target_id: str | None) -> str:
    if target_id is not None:
        return target_id
    targets = controller.list_targets(engagement_id)
    if len(targets) == 1:
        return targets[0].target_id
    if not targets:
        raise typer.BadParameter("engagement has no registered targets; run `target sync` first")
    raise typer.BadParameter("multiple targets exist; pass --target")


def _format_plan(plan: ActionPlan) -> str:
    lines = [f"request: {plan.request.request_id}", f"decision: {plan.decision.reason_code.value}"]
    if plan.decision.reasons:
        lines.append("reasons: " + "; ".join(plan.decision.reasons))
    if plan.approval_request is not None:
        lines.append(f"approval required: {plan.approval_request.approval_id}")
        lines.append(f"expires: {plan.approval_request.expires_at.isoformat()}")
    if plan.outcome is not None:
        lines.append(f"attempt: {plan.outcome.attempt.attempt_id}")
        lines.append(f"status: {plan.outcome.run_result.status.value}")
        lines.append(f"findings: {len(plan.outcome.findings)}")
        for finding in plan.outcome.findings:
            lines.append(f"  - {finding.finding_id} {finding.finding_type}: {finding.title}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Initialization and health
# ---------------------------------------------------------------------------
@app.command()
def init(ctx: typer.Context) -> None:
    """Create the data directory, migrate SQLite, and install seed knowledge."""

    with _open(ctx) as container:
        payload = container.health()
    _emit(ctx, payload)
    _print(ctx, f"initialized {payload['database']}")
    _print(ctx, f"artifacts: {payload['artifacts']}")
    _print(ctx, f"signing key: {payload['signing_key_path']}")


@app.command()
def health(
    ctx: typer.Context,
    probe_exegol: bool = typer.Option(True, "--probe-exegol/--no-probe-exegol"),
) -> None:
    """Show local component health and, optionally, the Exegol endpoint."""

    with _open(ctx) as container:
        payload: dict[str, object] = dict(container.health())
        if probe_exegol:
            payload["exegol"] = container.probe_exegol()
    _emit(ctx, payload)
    if not _state(ctx).get("json"):
        console.print_json(data=_jsonable(payload))


# ---------------------------------------------------------------------------
# Engagements
# ---------------------------------------------------------------------------
@engagement_app.command("create")
def engagement_create(
    ctx: typer.Context,
    name: str = typer.Option(..., "--name", help="Human-readable engagement name."),
    mode: EngagementMode = typer.Option(EngagementMode.LAB, "--mode"),
    program_id: str | None = typer.Option(None, "--program-id"),
    notes: str = typer.Option("", "--notes"),
) -> None:
    """Create an engagement in the CREATED state."""

    with _open(ctx) as container:
        engagement = Controller(container).create_engagement(
            name=name, mode=mode, program_id=program_id, notes=notes
        )
    _emit(ctx, engagement)
    _print(ctx, engagement.engagement_id)


@engagement_app.command("list")
def engagement_list(ctx: typer.Context, limit: int = typer.Option(100, "--limit")) -> None:
    """List engagements."""

    with _open(ctx) as container:
        engagements = Controller(container).list_engagements(limit=limit)
    _emit(ctx, engagements)
    if not _state(ctx).get("json"):
        _table(
            "Engagements",
            ("ID", "Name", "State", "Mode", "Updated"),
            [
                (e.engagement_id, e.name, e.state.value, e.mode.value, e.updated_at.isoformat())
                for e in engagements
            ],
        )


@engagement_app.command("show")
def engagement_show(ctx: typer.Context, engagement_id: str = typer.Argument(...)) -> None:
    """Show one engagement."""

    with _open(ctx) as container:
        engagement = Controller(container).get_engagement(_engagement_id(container, engagement_id))
    _emit(ctx, engagement)
    _print(ctx, engagement.model_dump_json(indent=2))


@engagement_app.command("close")
def engagement_close(
    ctx: typer.Context,
    engagement_id: str = typer.Argument(...),
    reason: str = typer.Option(..., "--reason"),
) -> None:
    """Close an engagement after all work is finished."""

    with _open(ctx) as container:
        engagement = Controller(container).close_engagement(
            _engagement_id(container, engagement_id), reason=reason
        )
    _emit(ctx, engagement)
    _print(ctx, f"{engagement.engagement_id}: {engagement.state.value}")


@engagement_app.command("resume")
def engagement_resume(
    ctx: typer.Context,
    engagement_id: str = typer.Argument(...),
    reason: str = typer.Option(..., "--reason"),
) -> None:
    """Recover a BLOCKED engagement at READY after operator investigation."""

    with _open(ctx) as container:
        engagement = Controller(container).resume_engagement(
            _engagement_id(container, engagement_id), reason=reason
        )
    _emit(ctx, engagement)
    _print(ctx, f"{engagement.engagement_id}: {engagement.state.value}")


@engagement_app.command("cancel")
def engagement_cancel(
    ctx: typer.Context,
    engagement_id: str = typer.Argument(...),
    reason: str = typer.Option(..., "--reason"),
) -> None:
    """Cancel an engagement without submitting anything."""

    with _open(ctx) as container:
        engagement = Controller(container).cancel_engagement(
            _engagement_id(container, engagement_id), reason=reason
        )
    _emit(ctx, engagement)
    _print(ctx, f"{engagement.engagement_id}: {engagement.state.value}")


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------
@scope_app.command("set")
def scope_set(
    ctx: typer.Context,
    engagement_id: str = typer.Argument(...),
    asset: list[str] = typer.Option(
        ...,
        "--asset",
        help="Asset as kind:value or a bare URL/domain/IPv4. Repeatable.",
    ),
    profile: list[str] | None = typer.Option(
        None,
        "--profile",
        help="Allowed reviewed profile. Repeatable. Defaults to low-risk HTTP profiles.",
    ),
    preapprove: list[str] | None = typer.Option(
        None,
        "--preapprove",
        help="Preauthorized low-risk profile. Repeatable. Defaults to the allowed low-risk set.",
    ),
    authorization_ref: str = typer.Option(..., "--authorization-ref"),
    approved_by: str = typer.Option(..., "--approved-by"),
    program_id: str = typer.Option("local-lab", "--program-id"),
    platform: str = typer.Option("none", "--platform"),
    contact: str | None = typer.Option(None, "--contact"),
    hours: int = typer.Option(8, "--hours", min=1, max=720),
    max_risk: RiskClass = typer.Option(RiskClass.LOW, "--max-risk"),
    allow_public_lab: bool = typer.Option(False, "--allow-public-lab"),
    approval_note: str = typer.Option("", "--approval-note"),
    scope_version: int = typer.Option(1, "--scope-version", min=1),
) -> None:
    """Compile and seal a human-approved scope.

    The default profile set is the reviewed low-risk HTTP surface. Active
    profiles must be added explicitly and are never preauthorized.
    """

    now = utc_now()
    default_profiles = [
        "http.baseline",
        "http.security_headers",
        "http.exposed_files",
        "http.cors",
    ]
    profiles = tuple(dict.fromkeys(profile or default_profiles))
    preapproved = tuple(
        dict.fromkeys(
            preapprove
            if preapprove is not None
            else [item for item in profiles if item in default_profiles]
        )
    )

    with _open(ctx) as container:
        resolved = _engagement_id(container, engagement_id)
        engagement = container.repos.engagements.get(resolved)
        if engagement is None:
            _fail(f"unknown engagement: {engagement_id}")
        unknown = [item for item in profiles if container.profiles.get(item) is None]
        if unknown:
            _fail(f"unknown profiles: {', '.join(unknown)}")
        draft = ScopeDraft(
            engagement_id=resolved,
            program_id=program_id,
            mode=engagement.mode,
            assets=tuple(_parse_asset(spec, now=now) for spec in asset),
            allowed_profiles=profiles,
            preapproved_profiles=preapproved,
            testing_window=TestingWindow(
                starts_at=now - timedelta(minutes=5),
                ends_at=now + timedelta(hours=hours),
            ),
            roe=ROEConstraints(
                max_risk_class=max_risk,
                allowed_side_effects=(SideEffectClass.NONE, SideEffectClass.READ_ONLY),
            ),
            reporting=ReportingRules(platform=platform, contact=contact),
            authorization_ref=authorization_ref,
            allow_public_lab=allow_public_lab,
        )
        scope = Controller(container).set_scope(
            resolved,
            draft,
            approved_by=approved_by,
            approval_note=approval_note,
            version=scope_version,
        )
    _emit(ctx, scope)
    _print(ctx, f"{scope.scope_id} v{scope.version} sealed for {scope.engagement_id}")
    _print(ctx, f"assets: {len(scope.assets)}  profiles: {len(scope.allowed_profiles)}")


@scope_app.command("show")
def scope_show(ctx: typer.Context, engagement_id: str = typer.Argument(...)) -> None:
    """Show the sealed scope for an engagement."""

    with _open(ctx) as container:
        scope = Controller(container).get_scope(_engagement_id(container, engagement_id))
    _emit(ctx, scope)
    _print(ctx, scope.model_dump_json(indent=2))


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------
@target_app.command("add")
def target_add(
    ctx: typer.Context,
    engagement_id: str = typer.Argument(...),
    asset_id: str = typer.Option(..., "--asset-id"),
    url: str | None = typer.Option(None, "--url"),
    host: str | None = typer.Option(None, "--host"),
    scheme: str = typer.Option("https", "--scheme"),
    port: int | None = typer.Option(None, "--port"),
    notes: str = typer.Option("", "--notes"),
) -> None:
    """Register a target derived from an approved scope asset."""

    with _open(ctx) as container:
        target = Controller(container).add_target(
            _engagement_id(container, engagement_id),
            asset_id=asset_id,
            url=url,
            host=host,
            scheme=scheme,
            port=port,
            notes=notes,
        )
    _emit(ctx, target)
    _print(ctx, f"{target.target_id} {target.base_url}")


@target_app.command("sync")
def target_sync(ctx: typer.Context, engagement_id: str = typer.Argument(...)) -> None:
    """Register targets for every URL/domain/IPv4 asset in the scope."""

    with _open(ctx) as container:
        targets = Controller(container).sync_targets(_engagement_id(container, engagement_id))
    _emit(ctx, targets)
    if not _state(ctx).get("json"):
        _table(
            "Targets",
            ("ID", "Asset", "Base URL", "Source"),
            [(t.target_id, t.asset_id, t.base_url, t.source) for t in targets],
        )


@target_app.command("list")
def target_list(ctx: typer.Context, engagement_id: str = typer.Argument(...)) -> None:
    """List registered targets."""

    with _open(ctx) as container:
        targets = Controller(container).list_targets(_engagement_id(container, engagement_id))
    _emit(ctx, targets)
    if not _state(ctx).get("json"):
        _table(
            "Targets",
            ("ID", "Asset", "Base URL", "Source"),
            [(t.target_id, t.asset_id, t.base_url, t.source) for t in targets],
        )


# ---------------------------------------------------------------------------
# Scanning and execution
# ---------------------------------------------------------------------------
@app.command()
def scan(
    ctx: typer.Context,
    engagement_id: str = typer.Argument(...),
    profile: str = typer.Option(..., "--profile"),
    target: str | None = typer.Option(None, "--target"),
    approve_by: str | None = typer.Option(
        None,
        "--approve-by",
        help="Named human; immediately approves a pending request and executes.",
    ),
    reason: str = typer.Option("", "--reason"),
    note: str = typer.Option("", "--note"),
) -> None:
    """Request one reviewed profile against one registered target."""

    with _open(ctx) as container:
        controller = Controller(container)
        resolved = _engagement_id(container, engagement_id)
        plan = controller.request_action(
            engagement_id=resolved,
            profile_id=profile,
            target_id=_resolve_target(controller, resolved, target),
            requested_by=container.settings.operator,
            reason=reason,
        )
        if plan.approval_request is not None and approve_by:
            outcome = controller.approve_action(
                plan.approval_request.approval_id,
                approved_by=approve_by,
                note=note,
                execute=True,
            )
            plan = ActionPlan(
                request=plan.request,
                decision=plan.decision,
                approval_request=plan.approval_request,
                outcome=outcome.outcome,
            )
    _emit(ctx, plan)
    _print(ctx, _format_plan(plan))
    if plan.approval_request is not None and plan.outcome is None:
        raise typer.Exit(3)


@app.command()
def execute(
    ctx: typer.Context,
    request_id: str = typer.Argument(...),
    approval_id: str | None = typer.Option(None, "--approval-id"),
) -> None:
    """Execute a previously approved action request."""

    with _open(ctx) as container:
        outcome = Controller(container).execute_request(request_id, approval_id=approval_id)
    _emit(ctx, outcome)
    if not _state(ctx).get("json"):
        _print(ctx, f"attempt {outcome.attempt.attempt_id}: {outcome.run_result.status.value}")
        _print(ctx, f"findings: {len(outcome.findings)}")
        for finding in outcome.findings:
            _print(ctx, f"  {finding.finding_id} {finding.finding_type}: {finding.title}")


# ---------------------------------------------------------------------------
# Approvals
# ---------------------------------------------------------------------------
@approvals_app.command("list")
def approvals_list(ctx: typer.Context, engagement_id: str = typer.Argument(...)) -> None:
    """List pending approvals for an engagement."""

    with _open(ctx) as container:
        pending = Controller(container).pending_approvals(_engagement_id(container, engagement_id))
    _emit(ctx, pending)
    if not _state(ctx).get("json"):
        _table(
            "Pending approvals",
            ("ID", "Request", "Expires"),
            [(item.approval_id, item.request_id, item.expires_at.isoformat()) for item in pending],
        )


@approvals_app.command("approve")
def approvals_approve(
    ctx: typer.Context,
    approval_id: str = typer.Argument(...),
    approved_by: str = typer.Option(..., "--by"),
    note: str = typer.Option("", "--note"),
    execute_now: bool = typer.Option(True, "--execute/--no-execute"),
) -> None:
    """Grant a named-human approval and optionally execute immediately."""

    with _open(ctx) as container:
        outcome = Controller(container).approve_action(
            approval_id, approved_by=approved_by, note=note, execute=execute_now
        )
    _emit(ctx, outcome)
    if not _state(ctx).get("json"):
        _print(ctx, f"approved {outcome.record.approval_id} by {outcome.record.approved_by}")
        if outcome.outcome is not None:
            attempt = outcome.outcome.attempt.attempt_id
            status = outcome.outcome.run_result.status.value
            _print(ctx, f"attempt {attempt}: {status}")


@approvals_app.command("reject")
def approvals_reject(
    ctx: typer.Context,
    approval_id: str = typer.Argument(...),
    rejected_by: str = typer.Option(..., "--by"),
    note: str = typer.Option("", "--note"),
) -> None:
    """Reject a pending approval request."""

    with _open(ctx) as container:
        record = Controller(container).reject_action(
            approval_id, rejected_by=rejected_by, note=note
        )
    _emit(ctx, record)
    _print(ctx, f"rejected {record.approval_id}")


# ---------------------------------------------------------------------------
# Validation and review
# ---------------------------------------------------------------------------
@app.command()
def validate(
    ctx: typer.Context,
    engagement_id: str = typer.Argument(...),
    finding: list[str] = typer.Option(..., "--finding", help="Tool finding ID. Repeatable."),
    bug_class: str = typer.Option(..., "--bug-class"),
    title: str = typer.Option(..., "--title"),
    claim: str = typer.Option(..., "--claim"),
    severity: SeverityBand = typer.Option(SeverityBand.MEDIUM, "--severity"),
    cvss: str | None = typer.Option(None, "--cvss"),
    impact: str | None = typer.Option(None, "--impact"),
    exploitability: str = typer.Option("", "--exploitability"),
    uncertainty: str = typer.Option("", "--uncertainty"),
    repetitions: int | None = typer.Option(None, "--repetitions"),
) -> None:
    """Submit tool findings to the deterministic validation pipeline."""

    with _open(ctx) as container:
        outcome = Controller(container).validate_finding(
            engagement_id=_engagement_id(container, engagement_id),
            tool_finding_ids=tuple(finding),
            bug_class_id=bug_class,
            title=title,
            claim=claim,
            severity_band=severity,
            cvss_vector=cvss,
            impact_summary=impact,
            exploitability_summary=exploitability,
            uncertainty=uncertainty,
            performed_repetitions=repetitions,
        )
    _emit(ctx, outcome)
    if not _state(ctx).get("json"):
        _print(ctx, f"finding {outcome.finding.finding_id}: {outcome.status.value}")
        for gate in outcome.finding.gates:
            _print(ctx, f"  {gate.gate.value}: {gate.status.value} — {gate.reason[:160]}")


@app.command()
def review(
    ctx: typer.Context,
    finding_id: str = typer.Argument(...),
    reviewer: str = typer.Option(..., "--reviewer"),
    decision: HumanReviewStatus = typer.Option(..., "--decision"),
    notes: str = typer.Option("", "--notes"),
) -> None:
    """Record a human decision on a validated finding."""

    with _open(ctx) as container:
        outcome = Controller(container).review_finding(
            finding_id,
            reviewer=reviewer,
            decision=decision,
            notes=notes,
        )
    _emit(ctx, outcome)
    _print(ctx, f"{outcome.review.finding_id}: {outcome.review.decision.value}")


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
@findings_app.command("list")
def findings_list(ctx: typer.Context, engagement_id: str = typer.Argument(...)) -> None:
    """List tool findings and validated findings."""

    with _open(ctx) as container:
        resolved = _engagement_id(container, engagement_id)
        status = Controller(container).status(resolved)
    _emit(ctx, {"tool_findings": status.tool_findings, "validated_findings": status.validated_findings})
    if not _state(ctx).get("json"):
        _table(
            "Tool findings",
            ("ID", "Type", "Confidence", "Title"),
            [(f.finding_id, f.finding_type, f.confidence.value, f.title) for f in status.tool_findings],
        )
        _table(
            "Validated findings",
            ("ID", "Status", "Severity", "Review", "Title"),
            [
                (
                    f.finding_id,
                    f.status.value,
                    f.severity.band.value,
                    f.human_review_status.value,
                    f.title,
                )
                for f in status.validated_findings
            ],
        )


@findings_app.command("show")
def findings_show(ctx: typer.Context, finding_id: str = typer.Argument(...)) -> None:
    """Show one tool or validated finding by ID."""

    with _open(ctx) as container:
        tool = container.repos.findings.get(finding_id)
        if tool is not None:
            _emit(ctx, tool)
            _print(ctx, tool.model_dump_json(indent=2))
            return
        validated = container.repos.validations.get(finding_id)
    if validated is None:
        _fail(f"unknown finding: {finding_id}")
    _emit(ctx, validated)
    _print(ctx, validated.model_dump_json(indent=2))


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
@report_app.command("draft")
def report_draft(
    ctx: typer.Context,
    engagement_id: str = typer.Argument(...),
    finding: list[str] | None = typer.Option(None, "--finding"),
    title: str | None = typer.Option(None, "--title"),
    summary: str | None = typer.Option(None, "--summary"),
    impact: str | None = typer.Option(None, "--impact"),
    remediation: str = typer.Option("", "--remediation"),
    reference: list[str] | None = typer.Option(None, "--reference"),
    platform: str | None = typer.Option(None, "--platform"),
    destination: str = typer.Option("manual", "--destination"),
    include_unapproved: bool = typer.Option(False, "--include-unapproved"),
) -> None:
    """Draft a report from passed, unique, human-approved findings."""

    with _open(ctx) as container:
        report = Controller(container).draft_report(
            engagement_id=_engagement_id(container, engagement_id),
            finding_ids=tuple(finding or ()),
            title=title,
            summary=summary,
            impact=impact,
            remediation=remediation,
            references=tuple(reference or ()),
            platform=platform,
            destination=destination,
            require_approved=not include_unapproved,
        )
    _emit(ctx, report)
    _print(ctx, f"{report.report_id}: {report.status.value} ({report.content_hash[:16]})")


@report_app.command("request")
def report_request(ctx: typer.Context, report_id: str = typer.Argument(...)) -> None:
    """Mark a draft as pending submission approval."""

    with _open(ctx) as container:
        report = Controller(container).request_report_approval(report_id)
    _emit(ctx, report)
    _print(ctx, f"{report.report_id}: {report.status.value}")


@report_app.command("approve")
def report_approve(
    ctx: typer.Context,
    report_id: str = typer.Argument(...),
    approved_by: str = typer.Option(..., "--by"),
    destination: str = typer.Option(..., "--destination"),
    note: str = typer.Option("", "--note"),
) -> None:
    """Record explicit human approval for the exact report content and destination."""

    with _open(ctx) as container:
        report = Controller(container).approve_report(
            report_id, approved_by=approved_by, destination=destination, note=note
        )
    _emit(ctx, report)
    _print(ctx, f"{report.report_id}: {report.status.value}")


@report_app.command("submit")
def report_submit(ctx: typer.Context, report_id: str = typer.Argument(...)) -> None:
    """Mark an approved report submitted and close the engagement."""

    with _open(ctx) as container:
        report = Controller(container).submit_report(report_id)
    _emit(ctx, report)
    _print(ctx, f"{report.report_id}: {report.status.value}")


@report_app.command("withdraw")
def report_withdraw(
    ctx: typer.Context,
    report_id: str = typer.Argument(...),
    reason: str = typer.Option(..., "--reason"),
) -> None:
    """Withdraw a draft or pending report."""

    with _open(ctx) as container:
        report = Controller(container).withdraw_report(report_id, reason=reason)
    _emit(ctx, report)
    _print(ctx, f"{report.report_id}: {report.status.value}")


@report_app.command("list")
def report_list(ctx: typer.Context, engagement_id: str = typer.Argument(...)) -> None:
    """List reports for an engagement."""

    with _open(ctx) as container:
        resolved = _engagement_id(container, engagement_id)
        reports = container.repos.reports.list_by_engagement(resolved)
    _emit(ctx, reports)
    if not _state(ctx).get("json"):
        _table(
            "Reports",
            ("ID", "Status", "Destination", "Findings", "Hash"),
            [
                (r.report_id, r.status.value, r.destination, len(r.finding_ids), r.content_hash[:16])
                for r in reports
            ],
        )


@report_app.command("show")
def report_show(ctx: typer.Context, report_id: str = typer.Argument(...)) -> None:
    """Show one report."""

    with _open(ctx) as container:
        report = container.reports.get(report_id)
    if report is None:
        _fail(f"unknown report: {report_id}")
    _emit(ctx, report)
    _print(ctx, report.model_dump_json(indent=2))


# ---------------------------------------------------------------------------
# Status, reasoning, audit
# ---------------------------------------------------------------------------
@app.command()
def status(ctx: typer.Context, engagement_id: str = typer.Argument(...)) -> None:
    """Show durable state, budget, targets, findings, approvals, and audit health."""

    with _open(ctx) as container:
        payload = Controller(container).status(_engagement_id(container, engagement_id))
    _emit(ctx, payload)
    if _state(ctx).get("json"):
        return
    engagement = payload.engagement
    console.print(
        f"[bold]{engagement.engagement_id}[/bold] {engagement.name} "
        f"[cyan]{engagement.state.value}[/cyan] ({engagement.mode.value})"
    )
    console.print(
        f"scope: {payload.scope.scope_id if payload.scope else 'none'}  "
        f"budget actions: {payload.budget.remaining_actions}/{payload.budget.limits.max_actions} remaining  "
        f"audit: {'valid' if payload.audit.valid else 'INVALID'}"
    )
    if payload.targets:
        _table(
            "Targets",
            ("ID", "Base URL", "Source"),
            [(t.target_id, t.base_url, t.source) for t in payload.targets],
        )
    if payload.validated_findings:
        _table(
            "Validated findings",
            ("ID", "Status", "Severity", "Review", "Title"),
            [
                (
                    f.finding_id,
                    f.status.value,
                    f.severity.band.value,
                    f.human_review_status.value,
                    f.title,
                )
                for f in payload.validated_findings
            ],
        )
    if payload.pending_approvals:
        _table(
            "Pending approvals",
            ("ID", "Request", "Expires"),
            [(a.approval_id, a.request_id, a.expires_at.isoformat()) for a in payload.pending_approvals],
        )
    if payload.reports:
        _table(
            "Reports",
            ("ID", "Status", "Destination"),
            [(r.report_id, r.status.value, r.destination) for r in payload.reports],
        )


@app.command()
def reason(
    ctx: typer.Context,
    engagement_id: str = typer.Argument(...),
    objective: str = typer.Option(..., "--objective"),
    use_model: bool = typer.Option(False, "--use-model"),
    show_context: bool = typer.Option(False, "--show-context"),
) -> None:
    """Compile a fenced context packet and record an action-selection decision."""

    with _open(ctx) as container:
        result = Controller(container).reason(
            engagement_id=_engagement_id(container, engagement_id),
            objective=objective,
            use_model=use_model,
        )
    _emit(ctx, result)
    if _state(ctx).get("json"):
        return
    if show_context:
        console.print(result.rendered)
    if result.decision is None:
        _print(ctx, "no decision produced")
        for error in result.errors:
            _print(ctx, f"error: {error}")
        return
    decision = result.decision
    _print(ctx, f"{decision.decision_id}: {decision.action.value} — {decision.rationale_summary}")
    if decision.profile_id:
        _print(ctx, f"profile: {decision.profile_id}")
    if decision.target_id:
        _print(ctx, f"target: {decision.target_id}")


@audit_app.command("verify")
def audit_verify(
    ctx: typer.Context,
    engagement_id: str | None = typer.Option(None, "--engagement"),
) -> None:
    """Verify the append-only audit hash chain."""

    with _open(ctx) as container:
        resolved = _engagement_id(container, engagement_id) if engagement_id else None
        result = Controller(container).audit_verify(resolved)
    _emit(ctx, result)
    _print(ctx, f"audit chain: {'valid' if result.valid else 'INVALID'}")


@audit_app.command("list")
def audit_list(
    ctx: typer.Context,
    engagement_id: str | None = typer.Option(None, "--engagement"),
    limit: int = typer.Option(200, "--limit"),
) -> None:
    """List recent audit events."""

    with _open(ctx) as container:
        resolved = _engagement_id(container, engagement_id) if engagement_id else None
        events = Controller(container).audit_events(resolved, limit=limit)
    _emit(ctx, events)
    if not _state(ctx).get("json"):
        _table(
            "Audit events",
            ("Time", "Actor", "Action", "Outcome"),
            [
                (
                    e.occurred_at.isoformat(),
                    f"{e.actor.type.value}:{e.actor.id}",
                    e.action,
                    e.outcome,
                )
                for e in events
            ],
        )


# ---------------------------------------------------------------------------
# Lab
# ---------------------------------------------------------------------------
@lab_app.command("serve")
def lab_serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port", min=0, max=65535),
) -> None:
    """Run the deterministic vulnerable lab on loopback."""

    serve_lab(host=host, port=port)


@lab_app.command("endpoints")
def lab_endpoints(ctx: typer.Context) -> None:
    """Print the deterministic endpoints exposed by the lab."""

    payload = {
        "health": "/health",
        "env_exposure": "/.env",
        "git_head": "/.git/HEAD",
        "directory_listing": "/uploads/",
        "open_redirect": "/?next=https://huntress-canary.invalid/huntress-open-redirect",
        "reflection": "/?q=<marker>",
        "sql_error": "/?q=%27",
        "cors": "send Origin: https://huntress-canary.invalid",
    }
    _emit(ctx, payload)
    if not _state(ctx).get("json"):
        for name, endpoint in payload.items():
            _print(ctx, f"{name}: {endpoint}")


def main() -> None:
    """Console entry point with a single, predictable error surface."""

    try:
        app()
    except HuntressError as exc:
        error_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(2) from exc


if __name__ == "__main__":  # pragma: no cover
    main()


__all__ = ["app", "main"]
