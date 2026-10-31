"""Adapter that turns reviewed builtin profiles into execution results."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime

from huntress_contracts import (
    BuiltinBackendResult,
    Engagement,
    HttpMethod,
    ScopeDocument,
    TargetRecord,
    ToolFinding,
    ToolProfile,
    ToolRunStatus,
    new_id,
)
from huntress_evidence import ArtifactStore

from .handlers import BUILTIN_HANDLERS, DnsResolver, ScanContext, _system_dns_resolver
from .http import BoundedHttpClient
from .models import (
    FindingSpec,
    ScanAuthorizationError,
    ScanObservation,
    ScanRequestError,
    ScanTimeout,
)


class ScanningBackend:
    """Deterministic in-process executor for the builtin profile registry."""

    def __init__(
        self,
        store: ArtifactStore,
        *,
        dns_resolver: DnsResolver | None = None,
        verify_tls: bool = True,
    ) -> None:
        self._store = store
        self._dns_resolver = dns_resolver or _system_dns_resolver
        self._verify_tls = verify_tls

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
    ) -> BuiltinBackendResult:
        handler = BUILTIN_HANDLERS.get(profile.builtin_handler or "")
        if handler is None:
            return BuiltinBackendResult(
                status=ToolRunStatus.FAILED,
                error_code="handler_missing",
                error_message=f"no builtin handler registered for {profile.builtin_handler!r}",
            )

        client = BoundedHttpClient(
            max_response_bytes=profile.max_output_bytes,
            timeout_seconds=float(profile.timeout_seconds),
            verify_tls=self._verify_tls,
        )
        ctx = ScanContext(
            engagement=engagement,
            target=target,
            scope=scope,
            profile=profile,
            store=self._store,
            http=client,
            authorize_url=authorize_url,
            action_request_id=action_request_id,
            policy_version=policy_version,
            scope_hash=scope_hash,
            now=now,
            dns_resolver=self._dns_resolver,
        )
        try:
            observation = handler(ctx)
        except ScanAuthorizationError as exc:
            return self._failure(
                ctx,
                status=ToolRunStatus.BLOCKED,
                error_code="scope_denied",
                message=str(exc),
            )
        except ScanTimeout as exc:
            return self._failure(
                ctx,
                status=ToolRunStatus.TIMEOUT,
                error_code="timeout",
                message=str(exc),
            )
        except ScanRequestError as exc:
            return self._failure(
                ctx,
                status=ToolRunStatus.FAILED,
                error_code="request_failed",
                message=str(exc),
            )
        except Exception as exc:
            return self._failure(
                ctx,
                status=ToolRunStatus.FAILED,
                error_code="handler_error",
                message=f"{type(exc).__name__}: {exc}",
            )
        finally:
            client.close()

        materialized = (
            self._materialize_spec(profile, engagement, target, spec, observation, now)
            for spec in observation.findings
        )
        findings = tuple(finding for finding in materialized if finding is not None)
        summary = {
            "profile_id": profile.profile_id,
            "profile_version": profile.version,
            "request_count": observation.request_count,
            "findings": [finding.finding_type for finding in findings],
            "artifact_refs": list(observation.artifact_refs),
            "notes": observation.notes,
        }
        return BuiltinBackendResult(
            status=ToolRunStatus.SUCCEEDED,
            exit_code=0,
            stdout=json.dumps(summary, indent=2, sort_keys=True).encode("utf-8"),
            request_count=observation.request_count,
            artifact_refs=observation.artifact_refs,
            findings=findings,
            output_truncated=observation.output_truncated,
        )

    def _failure(
        self,
        ctx: ScanContext,
        *,
        status: ToolRunStatus,
        error_code: str,
        message: str,
    ) -> BuiltinBackendResult:
        return BuiltinBackendResult(
            status=status,
            exit_code=1 if status is ToolRunStatus.FAILED else None,
            stderr=message.encode("utf-8"),
            request_count=ctx.request_count,
            artifact_refs=tuple(ctx.artifact_refs),
            output_truncated=ctx.truncated,
            error_code=error_code,
            error_message=message[:2000],
        )

    @staticmethod
    def _materialize_spec(
        profile: ToolProfile,
        engagement: Engagement,
        target: TargetRecord,
        spec: FindingSpec,
        observation: ScanObservation,
        now: datetime,
    ) -> ToolFinding | None:
        return ToolFinding(
            finding_id=new_id("tf"),
            engagement_id=engagement.engagement_id,
            target_id=target.target_id,
            tool_profile_id=profile.profile_id,
            tool_version=profile.version,
            parser_version="1.0",
            workstream=profile.workstream,
            finding_type=spec.finding_type,
            title=spec.title,
            bug_class_id=spec.bug_class_id,
            cwe_ids=spec.cwe_ids,
            signature_ref=spec.signature_ref,
            confidence=spec.confidence,
            oracle_hint=spec.oracle_hint,
            artifact_refs=spec.artifact_refs,
            observed_at=observation.observed_at or now,
            excerpt=spec.excerpt[:4000],
            details=dict(spec.details),
            evidence_fingerprint=spec.evidence_fingerprint,
        )
