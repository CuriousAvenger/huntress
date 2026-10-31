"""CVSS scoring, severity inputs, reproduction policy, and proof oracles."""

from __future__ import annotations

from pathlib import Path

import pytest
from huntress_contracts import (
    GateStatus,
    OracleArchetype,
    SeverityBand,
    SideEffectClass,
    get_bug_class,
    sha256_hex,
    utc_now,
)
from huntress_evidence import ArtifactStore, artifact_provenance
from huntress_verification import (
    DEFAULT_REPRODUCTION_POLICY,
    ComponentMatchOracle,
    ContentMatchOracle,
    CryptographicProofOracle,
    DifferentialStatisticalOracle,
    ReproductionEvidence,
    SeverityAssessor,
    SeverityInputs,
    StateChangeAuthzOracle,
    score_vector,
)
from huntress_verification.oracles import OracleRequest
from tests.helpers import make_target


def _store(tmp_path: Path) -> ArtifactStore:
    return ArtifactStore(tmp_path / "artifacts")


def _put(store: ArtifactStore, text: str) -> str:
    return store.put_text(
        text,
        provenance=artifact_provenance(source_tool="pytest", engagement_id="eng_pytest000001"),
    ).sha256


def _request(
    store: ArtifactStore,
    *,
    archetype: OracleArchetype,
    refs: tuple[str, ...],
    facts: dict[str, str | int | float | bool] | None = None,
) -> OracleRequest:
    return OracleRequest(
        archetype=archetype,
        target=make_target("eng_pytest000001", "http://127.0.0.1:8080"),
        evidence_refs=refs,
        facts=facts or {},
        store=store,
        now=utc_now(),
    )


def test_cvss_31_known_vectors() -> None:
    critical = score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert critical.score == 9.8
    assert critical.band.value == "critical"
    assert critical.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    medium = score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
    assert medium.score == 6.1
    assert medium.band.value == "medium"

    none = score_vector("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N")
    assert none.score == 0.0
    assert none.band.value == "info"


@pytest.mark.parametrize(
    "vector",
    [
        "",
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/Z:X",
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ],
)
def test_cvss_rejects_invalid_vectors(vector: str) -> None:
    with pytest.raises(ValueError):
        score_vector(vector)


def test_severity_requires_demonstrated_inputs() -> None:
    bug_class = get_bug_class("bug_error_based_sqli")
    assessor = SeverityAssessor()

    hinted = assessor.assess(bug_class=bug_class, inputs=None)
    assert hinted.gate_status is GateStatus.INCONCLUSIVE
    assert hinted.assessment.method == "bug_class_hint"
    assert "not demonstrated impact" in hinted.reason

    explicit = assessor.assess(
        bug_class=bug_class,
        inputs=SeverityInputs(impact_summary="Database errors leak query structure.", band=SeverityBand.HIGH),
    )
    assert explicit.gate_status is GateStatus.PASS
    assert explicit.assessment.band.value == "high"

    scored = assessor.assess(
        bug_class=bug_class,
        inputs=SeverityInputs(
            impact_summary="Database errors leak query structure.",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        ),
    )
    assert scored.gate_status is GateStatus.PASS
    assert scored.assessment.cvss_score == 7.5
    assert scored.assessment.band.value == "high"


def test_severity_rejects_conflicting_or_invalid_inputs() -> None:
    bug_class = get_bug_class("bug_error_based_sqli")
    assessor = SeverityAssessor()
    conflicting = assessor.assess(
        bug_class=bug_class,
        inputs=SeverityInputs(
            impact_summary="Conflicting inputs.",
            band=SeverityBand.LOW,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ),
    )
    assert conflicting.gate_status is GateStatus.FAIL
    invalid = assessor.assess(
        bug_class=bug_class,
        inputs=SeverityInputs(impact_summary="Bad vector.", cvss_vector="not-a-vector"),
    )
    assert invalid.gate_status is GateStatus.FAIL


def test_reproduction_policy_counts_and_side_effects() -> None:
    sqli = get_bug_class("bug_error_based_sqli")
    exposed = get_bug_class("bug_exposed_sensitive_file")
    policy = DEFAULT_REPRODUCTION_POLICY

    assert policy.required_repetitions(sqli, SideEffectClass.READ_ONLY) == 3
    assert policy.required_repetitions(exposed, SideEffectClass.READ_ONLY) == 1

    insufficient = policy.evaluate(
        bug_class=sqli,
        side_effect=SideEffectClass.READ_ONLY,
        evidence=ReproductionEvidence(performed_repetitions=2),
    )
    assert insufficient.gate_status is GateStatus.INCONCLUSIVE

    passed = policy.evaluate(
        bug_class=sqli,
        side_effect=SideEffectClass.READ_ONLY,
        evidence=ReproductionEvidence(performed_repetitions=3),
    )
    assert passed.gate_status is GateStatus.PASS

    not_independent = policy.evaluate(
        bug_class=sqli,
        side_effect=SideEffectClass.READ_ONLY,
        evidence=ReproductionEvidence(performed_repetitions=3, independent_confirmation=False),
    )
    assert not_independent.gate_status is GateStatus.INCONCLUSIVE

    repeated_material = policy.evaluate(
        bug_class=exposed,
        side_effect=SideEffectClass.MATERIAL,
        evidence=ReproductionEvidence(performed_repetitions=2),
    )
    assert repeated_material.gate_status is GateStatus.FAIL
    assert "side-effecting" in repeated_material.reason


def test_content_match_oracle_requires_evidence_and_expected_value(tmp_path: Path) -> None:
    store = _store(tmp_path)
    ref = _put(store, "DATABASE_PASSWORD=supersecret")
    oracle = ContentMatchOracle()

    passed = oracle.evaluate(
        _request(
            store,
            archetype=OracleArchetype.CONTENT_MATCH,
            refs=(ref,),
            facts={"content_ref": ref, "expected_text": "DATABASE_PASSWORD", "match_mode": "contains"},
        )
    )
    assert passed.status is GateStatus.PASS

    missing = oracle.evaluate(
        _request(store, archetype=OracleArchetype.CONTENT_MATCH, refs=(ref,), facts={"content_ref": ref})
    )
    assert missing.status is GateStatus.INCONCLUSIVE

    outside = oracle.evaluate(
        _request(
            store,
            archetype=OracleArchetype.CONTENT_MATCH,
            refs=(ref,),
            facts={"content_ref": "f" * 64, "expected_text": "x"},
        )
    )
    assert outside.status is GateStatus.FAIL


def test_differential_oracle_uses_repetitions_and_preserved_content(tmp_path: Path) -> None:
    store = _store(tmp_path)
    baseline_ref = _put(store, "all good")
    probe_ref = _put(store, "SQL syntax error in MySQL")
    oracle = DifferentialStatisticalOracle()
    facts = {
        "baseline_ref": baseline_ref,
        "probe_refs": probe_ref,
        "repetitions": 3,
        "signal": "error_signature",
        "error_signature": "SQL syntax error in MySQL",
    }
    passed = oracle.evaluate(
        _request(
            store,
            archetype=OracleArchetype.DIFFERENTIAL_STATISTICAL,
            refs=(baseline_ref, probe_ref),
            facts=facts,
        )
    )
    assert passed.status is GateStatus.PASS
    assert "1 unique probe artifact(s) across 3 independent trial(s)" in passed.reason

    insufficient = oracle.evaluate(
        _request(
            store,
            archetype=OracleArchetype.DIFFERENTIAL_STATISTICAL,
            refs=(baseline_ref, probe_ref),
            facts={**facts, "repetitions": 1},
        )
    )
    assert insufficient.status is GateStatus.INCONCLUSIVE

    leaked = oracle.evaluate(
        _request(
            store,
            archetype=OracleArchetype.DIFFERENTIAL_STATISTICAL,
            refs=(baseline_ref, probe_ref),
            facts={**facts, "baseline_ref": probe_ref},
        )
    )
    assert leaked.status is GateStatus.FAIL


def test_component_match_requires_confirmed_reachability(tmp_path: Path) -> None:
    store = _store(tmp_path)
    reachability = _put(store, "GET /component returned 200 with vulnerable behavior")
    oracle = ComponentMatchOracle()
    base = {
        "component": "example-lib",
        "version": "1.2.0",
        "affected_min": "1.0.0",
        "affected_max": "1.5.0",
        "reachability_ref": reachability,
        "reachability_confirmed": True,
    }
    passed = oracle.evaluate(
        _request(store, archetype=OracleArchetype.COMPONENT_MATCH, refs=(reachability,), facts=base)
    )
    assert passed.status is GateStatus.PASS

    unconfirmed = oracle.evaluate(
        _request(
            store,
            archetype=OracleArchetype.COMPONENT_MATCH,
            refs=(reachability,),
            facts={**base, "reachability_confirmed": False},
        )
    )
    assert unconfirmed.status is GateStatus.INCONCLUSIVE

    outside = oracle.evaluate(
        _request(
            store,
            archetype=OracleArchetype.COMPONENT_MATCH,
            refs=(reachability,),
            facts={**base, "version": "2.0.0"},
        )
    )
    assert outside.status is GateStatus.FAIL


def test_state_change_oracle_requires_unauthorized_identity(tmp_path: Path) -> None:
    store = _store(tmp_path)
    before = _put(store, "state=before")
    after = _put(store, "state=after")
    oracle = StateChangeAuthzOracle()
    base = {
        "before_state_ref": before,
        "after_state_ref": after,
        "identity": "unauthenticated",
        "state_changed": True,
    }
    passed = oracle.evaluate(
        _request(
            store,
            archetype=OracleArchetype.STATE_CHANGE_AUTHZ,
            refs=(before, after),
            facts=base,
        )
    )
    assert passed.status is GateStatus.PASS

    authorized = oracle.evaluate(
        _request(
            store,
            archetype=OracleArchetype.STATE_CHANGE_AUTHZ,
            refs=(before, after),
            facts={**base, "identity": "administrator"},
        )
    )
    assert authorized.status is GateStatus.FAIL

    unchanged = oracle.evaluate(
        _request(
            store,
            archetype=OracleArchetype.STATE_CHANGE_AUTHZ,
            refs=(before, before),
            facts={**base, "after_state_ref": before},
        )
    )
    assert unchanged.status is GateStatus.FAIL


def test_cryptographic_proof_oracle_verifies_artifact_hash(tmp_path: Path) -> None:
    store = _store(tmp_path)
    ref = _put(store, "proof bytes")
    oracle = CryptographicProofOracle()
    passed = oracle.evaluate(
        _request(
            store,
            archetype=OracleArchetype.CRYPTOGRAPHIC_PROOF,
            refs=(ref,),
            facts={
                "proof_type": "artifact_sha256",
                "artifact_ref": ref,
                "expected_sha256": sha256_hex("proof bytes"),
            },
        )
    )
    assert passed.status is GateStatus.PASS

    failed = oracle.evaluate(
        _request(
            store,
            archetype=OracleArchetype.CRYPTOGRAPHIC_PROOF,
            refs=(ref,),
            facts={
                "proof_type": "artifact_sha256",
                "artifact_ref": ref,
                "expected_sha256": sha256_hex("other bytes"),
            },
        )
    )
    assert failed.status is GateStatus.FAIL
