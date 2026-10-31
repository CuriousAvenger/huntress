"""Scope compilation, sealing, and deterministic guard behavior."""

from __future__ import annotations

from datetime import timedelta

import pytest
from huntress_contracts import (
    AssetKind,
    HttpMethod,
    RiskClass,
    ScopeExclusion,
    SideEffectClass,
    utc_now,
)
from huntress_contracts import (
    TestingWindow as WindowContract,
)
from huntress_governance import (
    ScopeCompileError,
    ScopeCompiler,
    ScopeGuard,
    scope_fingerprint,
    verify_scope_seal,
)
from tests.conftest import make_scope_draft
from tests.helpers import make_engagement, make_target

KEY = b"k" * 32


def _compile(draft, *, key: bytes = KEY, approved_at=None):
    from huntress_execution import ALL_PROFILES

    return ScopeCompiler(key).compile(
        draft,
        profiles=ALL_PROFILES,
        approved_by="Approver",
        approved_at=approved_at,
        scope_id="scope_pytest000001",
    )


def test_compile_seals_scope_and_marks_assets_approved() -> None:
    draft = make_scope_draft(engagement_id="eng_pytest000001", url="http://127.0.0.1:8080")
    scope = _compile(draft)
    assert scope.approved_by == "Approver"
    assert scope.signature
    assert all(asset.policy_status.value == "approved" for asset in scope.assets)
    assert verify_scope_seal(scope, KEY)
    assert not verify_scope_seal(scope, b"x" * 32)


def test_compile_is_deterministic_for_the_same_inputs() -> None:
    from datetime import UTC, datetime

    moment = datetime(2026, 1, 1, tzinfo=UTC)
    draft = make_scope_draft(engagement_id="eng_pytest000001", url="http://127.0.0.1:8080")
    first = _compile(draft, approved_at=moment)
    second = _compile(draft, approved_at=moment)
    assert first.content_hash == second.content_hash
    assert first.signature == second.signature


def test_tampering_with_a_sealed_scope_is_detected() -> None:
    draft = make_scope_draft(engagement_id="eng_pytest000001", url="http://127.0.0.1:8080")
    scope = _compile(draft)
    tampered = scope.model_copy(update={"program_id": "attacker-program"})
    assert not verify_scope_seal(tampered, KEY)
    tampered_hash = scope.model_copy(update={"content_hash": "0" * 64})
    assert not verify_scope_seal(tampered_hash, KEY)


def test_lab_mode_rejects_public_targets_without_explicit_override() -> None:
    draft = make_scope_draft(engagement_id="eng_pytest000001", url="https://example.com")
    with pytest.raises(ScopeCompileError, match="loopback/private"):
        _compile(draft)

    allowed = make_scope_draft(
        engagement_id="eng_pytest000001",
        url="https://example.com",
        allow_public_lab=True,
    )
    scope = _compile(allowed)
    assert scope.allow_public_lab is True


def test_compile_rejects_unknown_and_over_risk_profiles() -> None:
    unknown = make_scope_draft(
        engagement_id="eng_pytest000001",
        url="http://127.0.0.1:8080",
        profiles=("http.baseline", "http.not_real"),
        preapproved=("http.baseline",),
    )
    with pytest.raises(ScopeCompileError, match="unknown allowed profiles"):
        _compile(unknown)

    active = make_scope_draft(
        engagement_id="eng_pytest000001",
        url="http://127.0.0.1:8080",
        profiles=("http.baseline", "http.open_redirect"),
        preapproved=("http.baseline",),
        max_risk=RiskClass.LOW,
    )
    with pytest.raises(ScopeCompileError, match="exceeds ROE"):
        _compile(active)


def test_compile_refuses_to_preapprove_an_active_profile() -> None:
    draft = make_scope_draft(
        engagement_id="eng_pytest000001",
        url="http://127.0.0.1:8080",
        profiles=("http.baseline", "http.open_redirect"),
        preapproved=("http.baseline", "http.open_redirect"),
        max_risk=RiskClass.ACTIVE,
    )
    with pytest.raises(ScopeCompileError, match="cannot be preauthorized"):
        _compile(draft)


def test_guard_allows_matching_target_and_denies_method() -> None:
    draft = make_scope_draft(engagement_id="eng_pytest000001", url="http://127.0.0.1:8080")
    scope = _compile(draft)
    engagement = make_engagement(engagement_id=scope.engagement_id)
    target = make_target(scope.engagement_id, "http://127.0.0.1:8080", asset_id=scope.assets[0].asset_id)
    guard = ScopeGuard()

    allowed = guard.check_target(
        engagement=engagement,
        scope=scope,
        target=target,
        method=HttpMethod.GET,
        now=utc_now(),
        signing_key=KEY,
    )
    assert allowed.allowed
    denied = guard.check_target(
        engagement=engagement,
        scope=scope,
        target=target,
        method=HttpMethod.POST,
        now=utc_now(),
        signing_key=KEY,
    )
    assert not denied.allowed
    assert denied.reason_code.value == "denied_method_not_allowed"


def test_guard_denies_exclusions_and_expired_windows() -> None:
    draft = make_scope_draft(engagement_id="eng_pytest000001", url="http://127.0.0.1:8080")
    now = utc_now()
    draft = draft.model_copy(
        update={
            "exclusions": (
                ScopeExclusion(
                    exclusion_id="excl_pytest000001",
                    kind=AssetKind.IPV4,
                    value="127.0.0.1",
                    reason="pytest exclusion",
                    created_at=now,
                ),
            )
        }
    )
    scope = _compile(draft)
    engagement = make_engagement(engagement_id=scope.engagement_id)
    target = make_target(scope.engagement_id, "http://127.0.0.1:8080", asset_id=scope.assets[0].asset_id)
    guard = ScopeGuard()

    excluded = guard.check_target(
        engagement=engagement,
        scope=scope,
        target=target,
        method=HttpMethod.GET,
        now=now,
        signing_key=KEY,
    )
    assert excluded.reason_code.value == "denied_target_excluded"

    expired = guard.check_target(
        engagement=engagement,
        scope=scope,
        target=target,
        method=HttpMethod.GET,
        now=scope.testing_window.ends_at + timedelta(seconds=1),
        signing_key=KEY,
    )
    assert expired.reason_code.value == "denied_scope_expired"


def test_guard_denies_target_from_another_engagement_and_unsealed_scope() -> None:
    draft = make_scope_draft(engagement_id="eng_pytest000001", url="http://127.0.0.1:8080")
    scope = _compile(draft)
    engagement = make_engagement(engagement_id=scope.engagement_id)
    other_target = make_target("eng_other00000001", "http://127.0.0.1:8080")
    guard = ScopeGuard()

    mismatch = guard.check_target(
        engagement=engagement,
        scope=scope,
        target=other_target,
        method=HttpMethod.GET,
        now=utc_now(),
        signing_key=KEY,
    )
    assert mismatch.reason_code.value == "denied_target_not_found"

    tampered = scope.model_copy(update={"approved_by": None})
    unsealed = guard.check_target(
        engagement=engagement,
        scope=tampered,
        target=make_target(
            scope.engagement_id, "http://127.0.0.1:8080", asset_id=scope.assets[0].asset_id
        ),
        method=HttpMethod.GET,
        now=utc_now(),
        signing_key=KEY,
    )
    assert unsealed.reason_code.value == "denied_scope_not_approved"


def test_redirect_checks_never_expand_scope() -> None:
    draft = make_scope_draft(engagement_id="eng_pytest000001", url="http://127.0.0.1:8080")
    scope = _compile(draft)
    guard = ScopeGuard()
    now = utc_now()

    inside = guard.check_redirect(
        scope=scope,
        url="http://127.0.0.1:8080/landing",
        method=HttpMethod.GET,
        now=now,
        signing_key=KEY,
    )
    assert inside.allowed
    outside = guard.check_redirect(
        scope=scope,
        url="http://169.254.169.254/latest/meta-data/",
        method=HttpMethod.GET,
        now=now,
        signing_key=KEY,
    )
    assert not outside.allowed
    assert outside.reason_code.value == "denied_redirect_not_in_scope"


def test_scope_fingerprint_changes_with_scope_content() -> None:
    draft = make_scope_draft(engagement_id="eng_pytest000001", url="http://127.0.0.1:8080")
    scope = _compile(draft)
    other = _compile(
        make_scope_draft(
            engagement_id="eng_pytest000001",
            url="http://127.0.0.1:8081",
        )
    )
    assert scope_fingerprint(scope) == scope_fingerprint(scope)
    assert scope_fingerprint(scope) != scope_fingerprint(other)


def test_testing_window_contains_normalizes_timezones() -> None:
    now = utc_now()
    window = WindowContract(starts_at=now - timedelta(minutes=1), ends_at=now + timedelta(hours=1))
    assert window.contains(now)
    assert not window.contains(now + timedelta(hours=2))


def test_side_effect_ranking_is_ordered() -> None:
    from huntress_contracts import side_effect_rank

    assert side_effect_rank(SideEffectClass.NONE) < side_effect_rank(SideEffectClass.READ_ONLY)
    assert side_effect_rank(SideEffectClass.READ_ONLY) < side_effect_rank(SideEffectClass.MATERIAL)
