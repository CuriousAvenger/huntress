"""Human approval lifecycle for high-risk actions.

An approval is bound to the exact action fingerprint and scope hash. It cannot
be reused for a different target, profile, evidence set, or scope version, and
it is sealed so database tampering is detectable.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from huntress_contracts import (
    ActionRequest,
    ApprovalRecord,
    ApprovalRequest,
    ApprovalStatus,
    ReasonCode,
    ScopeDocument,
    ensure_utc,
    new_id,
    utc_now,
)

from .hashing import approval_content_hash, sign, verify_approval_seal


@dataclass(frozen=True, slots=True)
class ApprovalCheck:
    valid: bool
    reason: str


class ApprovalService:
    """Create, approve, and verify human gates."""

    def create_request(
        self,
        *,
        request: ActionRequest,
        scope: ScopeDocument,
        requested_by: str,
        reason: str,
        ttl_seconds: int = 3600,
        now: datetime | None = None,
    ) -> ApprovalRequest:
        moment = ensure_utc(now) if now is not None else utc_now()
        return ApprovalRequest(
            approval_id=new_id("apr"),
            engagement_id=request.engagement_id,
            request_id=request.request_id,
            action_fingerprint=request.action_fingerprint(),
            scope_hash=scope.content_hash,
            requested_by=requested_by,
            requested_at=moment,
            reason=reason,
            expires_at=moment + timedelta(seconds=max(60, ttl_seconds)),
        )

    def approve(
        self,
        *,
        approval_request: ApprovalRequest,
        scope: ScopeDocument,
        approved_by: str,
        signing_key: bytes,
        note: str = "",
        ttl_seconds: int = 3600,
        now: datetime | None = None,
    ) -> ApprovalRecord:
        moment = ensure_utc(now) if now is not None else utc_now()
        if approval_request.status is not ApprovalStatus.PENDING:
            raise ValueError("only a pending approval request can be approved")
        record = ApprovalRecord(
            approval_id=approval_request.approval_id,
            engagement_id=approval_request.engagement_id,
            request_id=approval_request.request_id,
            action_fingerprint=approval_request.action_fingerprint,
            scope_hash=scope.content_hash,
            approved_by=approved_by,
            approved_at=moment,
            expires_at=moment + timedelta(seconds=max(60, ttl_seconds)),
            note=note,
            status=ApprovalStatus.APPROVED,
            content_hash="0" * 64,
            signature="",
        )
        digest = approval_content_hash(record)
        return record.model_copy(update={"content_hash": digest, "signature": sign(signing_key, digest)})

    def reject(
        self,
        *,
        approval_request: ApprovalRequest,
        scope: ScopeDocument,
        rejected_by: str,
        signing_key: bytes,
        note: str = "",
        now: datetime | None = None,
    ) -> ApprovalRecord:
        moment = ensure_utc(now) if now is not None else utc_now()
        record = ApprovalRecord(
            approval_id=approval_request.approval_id,
            engagement_id=approval_request.engagement_id,
            request_id=approval_request.request_id,
            action_fingerprint=approval_request.action_fingerprint,
            scope_hash=scope.content_hash,
            approved_by=rejected_by,
            approved_at=moment,
            expires_at=approval_request.expires_at,
            note=note,
            status=ApprovalStatus.REJECTED,
            content_hash="0" * 64,
            signature="",
        )
        digest = approval_content_hash(record)
        return record.model_copy(update={"content_hash": digest, "signature": sign(signing_key, digest)})

    def verify(
        self,
        *,
        approval: ApprovalRecord,
        request: ActionRequest,
        scope: ScopeDocument,
        signing_key: bytes,
        now: datetime | None = None,
    ) -> ApprovalCheck:
        moment = ensure_utc(now) if now is not None else utc_now()
        if approval.status is not ApprovalStatus.APPROVED:
            return ApprovalCheck(False, "approval is not in approved state")
        if approval.engagement_id != request.engagement_id:
            return ApprovalCheck(False, "approval belongs to a different engagement")
        if approval.action_fingerprint != request.action_fingerprint():
            return ApprovalCheck(False, "approval does not match the action fingerprint")
        if approval.scope_hash != scope.content_hash:
            return ApprovalCheck(False, "approval does not match the current scope hash")
        if moment < approval.approved_at:
            return ApprovalCheck(False, "approval is not yet valid")
        if moment > approval.expires_at:
            return ApprovalCheck(False, "approval has expired")
        if not verify_approval_seal(approval, signing_key):
            return ApprovalCheck(False, "approval seal is invalid")
        return ApprovalCheck(True, "approval verified")


def approval_denial_code(check: ApprovalCheck) -> ReasonCode:
    return ReasonCode.DENIED_APPROVAL_INVALID if check.valid is False else ReasonCode.ALLOWED
