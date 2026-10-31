"""Execution profile, run-result, and test-attempt contracts.

Profiles are code-reviewed configuration, never model output. An
``ExecutionRequest`` can only be constructed by the execution service after a
``PolicyDecision`` has allowed the corresponding ``ActionRequest``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import Field, field_validator, model_validator

from .base import Contract, ensure_utc
from .enums import (
    AssetKind,
    HttpMethod,
    OracleArchetype,
    ProfileExecutor,
    RiskClass,
    ScanWorkstream,
    SideEffectClass,
    ToolRunStatus,
)
from .findings import ToolFinding


class ToolProfile(Contract):
    """A fixed, reviewed operation with bounded arguments and resources.

    ``argv_template`` is only used by the Exegol executor. Each list element is
    substituted as one shell-quoted token; no element may contain shell
    metacharacters or a placeholder that resolves to model input. Builtin
    profiles name a registered Python handler instead.
    """

    profile_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,119}$")
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=2000)
    executor: ProfileExecutor
    workstream: ScanWorkstream
    risk_class: RiskClass
    side_effect_class: SideEffectClass
    requires_approval: bool = True
    preauthorizable: bool = False
    enabled_by_default: bool = False
    allowed_methods: tuple[HttpMethod, ...] = (HttpMethod.GET,)
    supported_asset_kinds: tuple[AssetKind, ...] = (
        AssetKind.DOMAIN,
        AssetKind.WILDCARD_DOMAIN,
        AssetKind.URL,
        AssetKind.IPV4,
        AssetKind.CIDR,
    )
    timeout_seconds: int = Field(default=120, ge=1, le=3600)
    max_output_bytes: int = Field(default=1_048_576, ge=1024, le=16_777_216)
    max_requests_per_run: int = Field(default=10, ge=1, le=500)
    builtin_handler: str | None = Field(default=None, max_length=120)
    argv_template: tuple[str, ...] = ()
    parser_id: str = Field(default="identity", max_length=120)
    oracle_hint: OracleArchetype | None = None
    tags: tuple[str, ...] = ()
    config_hash: str = Field(default="", max_length=64)

    @model_validator(mode="after")
    def _executor_shape(self) -> ToolProfile:
        if self.executor is ProfileExecutor.BUILTIN and not self.builtin_handler:
            raise ValueError("builtin profiles require builtin_handler")
        if self.executor is ProfileExecutor.EXEGOL and not self.argv_template:
            raise ValueError("exegol profiles require argv_template")
        if self.executor is ProfileExecutor.EXEGOL:
            for token in self.argv_template:
                if "\n" in token or "\x00" in token:
                    raise ValueError("argv template token contains control characters")
        if self.risk_class is RiskClass.EXPLOIT_LIKE and self.preauthorizable:
            raise ValueError("exploit-like profiles can never be preauthorized")
        if self.side_effect_class in {SideEffectClass.MATERIAL, SideEffectClass.DESTRUCTIVE}:
            if self.preauthorizable:
                raise ValueError("material/destructive profiles cannot be preauthorized")
            if not self.requires_approval:
                raise ValueError("material/destructive profiles must require approval")
        if self.preauthorizable and self.risk_class not in {RiskClass.PASSIVE, RiskClass.LOW}:
            raise ValueError("only passive/low profiles may be preauthorizable")
        if self.preauthorizable and self.side_effect_class not in {
            SideEffectClass.NONE,
            SideEffectClass.READ_ONLY,
        }:
            raise ValueError("only no-side-effect/read-only profiles may be preauthorizable")
        return self


class ExecutionRequest(Contract):
    """Internal, fully-resolved request created only after a policy allow."""

    execution_id: str = Field(pattern=r"^exe_[a-zA-Z0-9_-]{6,80}$")
    engagement_id: str = Field(pattern=r"^eng_[a-zA-Z0-9_-]{6,80}$")
    request_id: str = Field(pattern=r"^req_[a-zA-Z0-9_-]{6,80}$")
    policy_decision_id: str = Field(pattern=r"^pol_[a-zA-Z0-9_-]{6,80}$")
    attempt_id: str = Field(pattern=r"^att_[a-zA-Z0-9_-]{6,80}$")
    target_id: str = Field(pattern=r"^tgt_[a-zA-Z0-9_-]{6,80}$")
    profile_id: str = Field(min_length=1, max_length=120)
    profile_version: str = Field(min_length=1, max_length=40)
    idempotency_key: str = Field(min_length=8, max_length=200)
    created_at: datetime
    deadline: datetime

    _created_utc = field_validator("created_at", "deadline")(ensure_utc)

    @model_validator(mode="after")
    def _deadline(self) -> ExecutionRequest:
        if self.deadline <= self.created_at:
            raise ValueError("execution deadline must be after creation")
        return self


class ToolRunResult(Contract):
    """Outcome of one profile invocation. Exit code alone is never success."""

    attempt_id: str = Field(pattern=r"^att_[a-zA-Z0-9_-]{6,80}$")
    execution_id: str = Field(pattern=r"^exe_[a-zA-Z0-9_-]{6,80}$")
    engagement_id: str = Field(pattern=r"^eng_[a-zA-Z0-9_-]{6,80}$")
    target_id: str = Field(pattern=r"^tgt_[a-zA-Z0-9_-]{6,80}$")
    profile_id: str = Field(min_length=1, max_length=120)
    profile_version: str = Field(min_length=1, max_length=40)
    status: ToolRunStatus
    exit_code: int | None = None
    started_at: datetime
    finished_at: datetime
    duration_ms: int = Field(ge=0)
    stdout_ref: str | None = Field(default=None, max_length=128)
    stderr_ref: str | None = Field(default=None, max_length=128)
    combined_ref: str | None = Field(default=None, max_length=128)
    artifact_refs: tuple[str, ...] = ()
    output_truncated: bool = False
    timed_out: bool = False
    error_code: str | None = Field(default=None, max_length=80)
    error_message: str = Field(default="", max_length=2000)
    request_count: int = Field(default=0, ge=0)
    side_effect_class: SideEffectClass
    backend: str = Field(default="fake", max_length=40)

    _run_utc = field_validator("started_at", "finished_at")(ensure_utc)

    @model_validator(mode="after")
    def _ordered(self) -> ToolRunResult:
        if self.finished_at < self.started_at:
            raise ValueError("finished_at must not precede started_at")
        if self.timed_out and self.status is not ToolRunStatus.TIMEOUT:
            raise ValueError("timed_out requires TIMEOUT status")
        return self


class BuiltinBackendResult(Contract):
    """Result of an in-process reviewed profile.

    This is an internal boundary object between the execution service and the
    scanning fleet. It is deliberately not persisted; the execution service
    turns it into artifacts, ``ToolFinding`` records, and a ``TestAttempt``.
    """

    status: ToolRunStatus
    exit_code: int | None = None
    stdout: bytes = b""
    stderr: bytes = b""
    request_count: int = Field(default=0, ge=0)
    artifact_refs: tuple[str, ...] = ()
    findings: tuple[ToolFinding, ...] = ()
    output_truncated: bool = False
    error_code: str | None = Field(default=None, max_length=80)
    error_message: str = Field(default="", max_length=2000)


class TestAttempt(Contract):
    """Durable record of an approved test, including its authorization trail."""

    attempt_id: str = Field(pattern=r"^att_[a-zA-Z0-9_-]{6,80}$")
    engagement_id: str = Field(pattern=r"^eng_[a-zA-Z0-9_-]{6,80}$")
    request_id: str = Field(pattern=r"^req_[a-zA-Z0-9_-]{6,80}$")
    policy_decision_id: str = Field(pattern=r"^pol_[a-zA-Z0-9_-]{6,80}$")
    target_id: str = Field(pattern=r"^tgt_[a-zA-Z0-9_-]{6,80}$")
    profile_id: str = Field(min_length=1, max_length=120)
    profile_version: str = Field(min_length=1, max_length=40)
    idempotency_key: str = Field(min_length=8, max_length=200)
    status: ToolRunStatus
    side_effect_class: SideEffectClass
    started_at: datetime
    finished_at: datetime
    artifact_refs: tuple[str, ...] = ()
    exit_code: int | None = None
    result_summary: str = Field(default="", max_length=2000)
    error_code: str | None = Field(default=None, max_length=80)
    result_ref: str | None = Field(default=None, max_length=128)

    _attempt_utc = field_validator("started_at", "finished_at")(ensure_utc)

    @model_validator(mode="after")
    def _ordered(self) -> TestAttempt:
        if self.finished_at < self.started_at:
            raise ValueError("finished_at must not precede started_at")
        return self


class RateLimitWindow(Contract):
    """Persisted per-host token-bucket state."""

    host: str = Field(min_length=1, max_length=253)
    window_started_at: datetime
    count: int = Field(ge=0)
    updated_at: datetime

    _rate_utc = field_validator("window_started_at", "updated_at")(ensure_utc)


class ScanCost(Contract):
    """Cost estimate used for budgeting before execution."""

    actions: int = Field(default=1, ge=0)
    requests: int = Field(default=1, ge=0)
    tokens: int = Field(default=0, ge=0)
    cost_usd: Annotated[float, Field(ge=0.0)] = 0.0
