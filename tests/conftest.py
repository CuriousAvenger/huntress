"""Shared deterministic fixtures.

Every fixture uses a temporary data directory, the fake execution backend, and
loopback-only lab targets. No test reaches the public internet or a live
Exegol container.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest
from huntress_contracts import (
    AssetConfidence,
    AssetKind,
    EngagementMode,
    HttpMethod,
    RiskClass,
    ScopeAsset,
    ScopeDraft,
    SideEffectClass,
    TestingWindow,
    sha256_hex,
    utc_now,
)
from huntress_contracts.scope import AssetProvenance, ROEConstraints
from huntress_orchestrator.config import Settings, load_settings
from huntress_orchestrator.container import Container
from huntress_orchestrator.controller import Controller
from huntress_orchestrator.lab import LabServer, start_lab_server

LOW_RISK_PROFILES = (
    "http.baseline",
    "http.security_headers",
    "http.exposed_files",
    "http.cors",
)
ACTIVE_PROFILES = (
    "http.open_redirect",
    "http.reflected_marker",
    "http.error_based_sqli",
)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return load_settings(
        config_file=tmp_path / "absent.toml",
        data_dir=tmp_path / "data",
        mode=EngagementMode.LAB,
        exegol_backend="fake",
        operator="test-operator",
        reasoning_enabled=False,
        max_actions_per_engagement=1000,
        max_model_calls_per_engagement=100,
        max_tokens_per_engagement=1_000_000,
        max_cost_usd_per_engagement=100.0,
        max_wall_clock_seconds=86_400,
        max_requests_per_host_per_minute=600,
        max_requests_per_engagement_per_minute=3000,
        max_concurrency=2,
        approval_ttl_seconds=3600,
    )


@pytest.fixture
def container(settings: Settings) -> Iterator[Container]:
    instance = Container(settings)
    try:
        yield instance
    finally:
        instance.close()


@pytest.fixture
def controller(container: Container) -> Controller:
    return Controller(container)


@pytest.fixture
def lab() -> Iterator[LabServer]:
    server = start_lab_server("127.0.0.1", 0)
    try:
        yield server
    finally:
        server.stop()


def make_url_asset(url: str, *, asset_id: str | None = None) -> ScopeAsset:
    return ScopeAsset(
        asset_id=asset_id or "asset_" + sha256_hex(url)[:16],
        kind=AssetKind.URL,
        value=url,
        provenance=AssetProvenance(
            source="pytest",
            observed_at=utc_now(),
            confidence=AssetConfidence.CONFIRMED,
        ),
    )


def make_scope_draft(
    *,
    engagement_id: str,
    url: str,
    profiles: tuple[str, ...] = LOW_RISK_PROFILES,
    preapproved: tuple[str, ...] = LOW_RISK_PROFILES,
    max_risk: RiskClass = RiskClass.LOW,
    hours: int = 2,
    allow_public_lab: bool = False,
) -> ScopeDraft:
    now = utc_now()
    return ScopeDraft(
        engagement_id=engagement_id,
        program_id="pytest-lab",
        mode=EngagementMode.LAB,
        assets=(make_url_asset(url),),
        allowed_methods=(HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS),
        allowed_profiles=profiles,
        preapproved_profiles=preapproved,
        testing_window=TestingWindow(
            starts_at=now - timedelta(minutes=1),
            ends_at=now + timedelta(hours=hours),
        ),
        roe=ROEConstraints(
            max_risk_class=max_risk,
            allowed_side_effects=(SideEffectClass.NONE, SideEffectClass.READ_ONLY),
        ),
        authorization_ref="pytest local authorization",
        allow_public_lab=allow_public_lab,
    )


def setup_engagement(
    controller: Controller,
    *,
    url: str,
    profiles: tuple[str, ...] = LOW_RISK_PROFILES,
    preapproved: tuple[str, ...] = LOW_RISK_PROFILES,
    max_risk: RiskClass = RiskClass.LOW,
    name: str = "pytest engagement",
) -> tuple[str, str]:
    """Create an engagement, seal a scope, sync targets, and return IDs."""

    engagement = controller.create_engagement(name=name, mode=EngagementMode.LAB)
    controller.set_scope(
        engagement.engagement_id,
        make_scope_draft(
            engagement_id=engagement.engagement_id,
            url=url,
            profiles=profiles,
            preapproved=preapproved,
            max_risk=max_risk,
        ),
        approved_by="Test Approver",
        approval_note="pytest scope approval",
    )
    targets = controller.sync_targets(engagement.engagement_id)
    assert len(targets) == 1
    return engagement.engagement_id, targets[0].target_id
