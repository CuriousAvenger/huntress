"""Adapter from the in-process scanning fleet to the execution boundary."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Protocol

from huntress_contracts import (
    BuiltinBackendResult,
    Engagement,
    HttpMethod,
    ScopeDocument,
    TargetRecord,
    ToolProfile,
    ToolRunStatus,
)

from .models import BackendContext, BackendOutput


class BuiltinRunner(Protocol):
    def run(
        self,
        *,
        profile: ToolProfile,
        engagement: Engagement,
        target: TargetRecord,
        scope: ScopeDocument,
        authorize_url: Callable[[str, HttpMethod], bool],
        action_request_id: str,
        policy_version: str,
        scope_hash: str,
        now: datetime,
    ) -> BuiltinBackendResult: ...


class BuiltinBackend:
    """Execute a reviewed builtin profile through ``ScanningBackend``."""

    name = "builtin"

    def __init__(self, runner: BuiltinRunner) -> None:
        self._runner = runner

    def execute(self, context: BackendContext) -> BackendOutput:
        result = self._runner.run(
            profile=context.profile,
            engagement=context.engagement,
            target=context.target,
            scope=context.scope,
            authorize_url=context.authorize_url,
            action_request_id=context.request.request_id,
            policy_version=context.policy_version,
            scope_hash=context.scope_hash,
            now=context.now,
        )
        return BackendOutput(
            status=result.status,
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            request_count=result.request_count,
            findings=result.findings,
            artifact_refs=result.artifact_refs,
            output_truncated=result.output_truncated,
            timed_out=result.status is ToolRunStatus.TIMEOUT,
            error_code=result.error_code,
            error_message=result.error_message,
            backend=self.name,
        )
