"""Contract-level invariants: immutability, hashing, validation, and registry."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from huntress_contracts import (
    BUG_CLASSES,
    AssetKind,
    EngagementMode,
    HttpMethod,
    ProfileExecutor,
    RiskClass,
    ScanWorkstream,
    ScopeAsset,
    SideEffectClass,
    ToolProfile,
    band_for_cvss,
    canonical_json,
    ensure_utc,
    get_bug_class,
    new_id,
    sha256_hex,
    validate_id,
)
from huntress_contracts.enums import SeverityBand
from pydantic import ValidationError
from tests.helpers import make_scope_asset, make_target


def test_canonical_json_is_sorted_and_compact() -> None:
    assert canonical_json({"b": 2, "a": [1, 3]}) == '{"a":[1,3],"b":2}'
    assert sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_contracts_are_frozen() -> None:
    asset = make_scope_asset("https://lab.test")
    with pytest.raises(ValidationError):
        asset.value = "https://evil.test"  # type: ignore[misc]


def test_identifier_helpers() -> None:
    value = new_id("eng")
    assert validate_id(value, "eng") == value
    with pytest.raises(ValueError):
        validate_id("scope_123", "eng")
    with pytest.raises(ValueError):
        new_id("Eng")


def test_ensure_utc_rejects_naive_datetimes() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        ensure_utc(datetime(2025, 1, 1))
    assert ensure_utc(datetime(2025, 1, 1, tzinfo=UTC)).tzinfo is UTC


def test_scope_asset_normalization_and_validation() -> None:
    domain = ScopeAsset(
        asset_id="asset_example0001",
        kind=AssetKind.DOMAIN,
        value="Example.TEST.",
        provenance=make_scope_asset("https://example.test").provenance,
    )
    assert domain.value == "example.test"

    with pytest.raises(ValidationError, match="scheme"):
        ScopeAsset(
            asset_id="asset_example0002",
            kind=AssetKind.URL,
            value="ftp://example.test/file",
            provenance=domain.provenance,
        )
    with pytest.raises(ValidationError, match="userinfo"):
        ScopeAsset(
            asset_id="asset_example0003",
            kind=AssetKind.URL,
            value="https://user:pass@example.test/",
            provenance=domain.provenance,
        )
    with pytest.raises(ValidationError, match="query or fragment"):
        ScopeAsset(
            asset_id="asset_example0004",
            kind=AssetKind.URL,
            value="https://example.test/?q=1",
            provenance=domain.provenance,
        )


def test_target_requires_absolute_http_and_consistent_times() -> None:
    target = make_target("eng_pytest000001", "http://127.0.0.1:8080")
    assert target.port == 8080
    assert target.scheme == "http"

    from huntress_contracts import TargetRecord

    with pytest.raises(ValidationError, match="absolute http"):
        TargetRecord.model_validate({**target.model_dump(mode="python"), "base_url": "ftp://127.0.0.1/"})


def test_bug_class_registry_is_complete_and_oracle_bound() -> None:
    assert len(BUG_CLASSES) == 12
    for bug_class in BUG_CLASSES.values():
        assert bug_class.bug_class_id.startswith("bug_")
        assert bug_class.cwe_id >= 1
        assert get_bug_class(bug_class.bug_class_id) is bug_class
    with pytest.raises(KeyError):
        get_bug_class("bug_does_not_exist")


def test_tool_profile_executor_invariants() -> None:
    common = {
        "profile_id": "test.profile",
        "version": "1.0.0",
        "name": "Test",
        "description": "Test profile",
        "workstream": ScanWorkstream.SIGNATURE_CHECK,
        "risk_class": RiskClass.LOW,
        "side_effect_class": SideEffectClass.READ_ONLY,
        "allowed_methods": (HttpMethod.GET,),
    }
    with pytest.raises(ValidationError, match="builtin_handler"):
        ToolProfile(executor=ProfileExecutor.BUILTIN, **common)
    with pytest.raises(ValidationError, match="argv_template"):
        ToolProfile(executor=ProfileExecutor.EXEGOL, **common)
    with pytest.raises(ValidationError, match="exploit-like"):
        ToolProfile(
            **{**common, "risk_class": RiskClass.EXPLOIT_LIKE},
            executor=ProfileExecutor.BUILTIN,
            builtin_handler="handler",
            preauthorizable=True,
        )


def test_scope_draft_requires_future_window_and_assets() -> None:
    from huntress_contracts import ScopeDraft, TestingWindow

    now = datetime.now(UTC)
    with pytest.raises(ValidationError, match="ends_at"):
        TestingWindow(starts_at=now, ends_at=now)
    with pytest.raises(ValidationError, match="at least 1 item"):
        ScopeDraft(
            engagement_id="eng_pytest000001",
            program_id="pytest",
            mode=EngagementMode.LAB,
            assets=(),
            allowed_profiles=("http.baseline",),
            testing_window=TestingWindow(starts_at=now, ends_at=now + timedelta(hours=1)),
        )


def test_cvss_band_boundaries() -> None:
    assert band_for_cvss(0.0) is SeverityBand.INFO
    assert band_for_cvss(3.9) is SeverityBand.LOW
    assert band_for_cvss(4.0) is SeverityBand.MEDIUM
    assert band_for_cvss(6.9) is SeverityBand.MEDIUM
    assert band_for_cvss(7.0) is SeverityBand.HIGH
    assert band_for_cvss(8.9) is SeverityBand.HIGH
    assert band_for_cvss(9.0) is SeverityBand.CRITICAL
