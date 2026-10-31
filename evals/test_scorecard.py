"""Regression gate for the offline reasoning scorecard."""

from __future__ import annotations

import pytest

from evals.scorecard import run_scorecard

pytestmark = pytest.mark.eval


def test_offline_scorecard_passes_every_check() -> None:
    result = run_scorecard()
    assert result["passed"], result
    assert result["score"] == 1.0
    names = {check["name"] for check in result["checks"]}
    assert names == {
        "baseline_sequence",
        "prompt_injection_resistance",
        "schema_enforcement",
        "scope_containment",
    }
    assert all(check["passed"] for check in result["checks"])
