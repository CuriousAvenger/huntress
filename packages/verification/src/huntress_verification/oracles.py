"""Fixed, deterministic proof oracles.

Oracles consume artifacts and structured facts produced by deterministic
parsers. They never read model prose, confidence scores, or scanner severity
labels. Missing facts produce an inconclusive result, never a pass.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from huntress_contracts import GateStatus, OracleArchetype, TargetRecord, sha256_hex
from huntress_evidence import ArtifactStore, ArtifactStoreError
from packaging.version import InvalidVersion, Version

_REF_RE = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_VERIFIERS = frozenset({"hmac-sha256-v1", "ed25519", "sha256"})
_MAX_TEXT_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class OracleRequest:
    """Evidence and deterministic facts for one oracle evaluation."""

    archetype: OracleArchetype
    target: TargetRecord
    evidence_refs: tuple[str, ...]
    facts: Mapping[str, str | int | float | bool]
    store: ArtifactStore
    now: datetime


@dataclass(frozen=True, slots=True)
class OracleResult:
    status: GateStatus
    reason: str
    evidence_refs: tuple[str, ...] = ()
    oracle_id: str = ""
    oracle_version: str = "1.0"


class Oracle(Protocol):
    oracle_id: str
    archetype: OracleArchetype

    def evaluate(self, request: OracleRequest) -> OracleResult: ...


def _fact(request: OracleRequest, key: str) -> str | int | float | bool | None:
    return request.facts.get(key)


def _str_fact(request: OracleRequest, key: str) -> str | None:
    value = _fact(request, key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _int_fact(request: OracleRequest, key: str, default: int | None = None) -> int | None:
    value = _fact(request, key)
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _float_fact(request: OracleRequest, key: str, default: float | None = None) -> float | None:
    value = _fact(request, key)
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return default
    return default


def _bool_fact(request: OracleRequest, key: str) -> bool | None:
    value = _fact(request, key)
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in {"true", "false"}:
        return value.lower() == "true"
    return None


def _refs_fact(request: OracleRequest, key: str) -> tuple[str, ...]:
    value = _str_fact(request, key)
    if value is None:
        return ()
    refs = tuple(dict.fromkeys(part.strip() for part in value.split(",") if part.strip()))
    if any(not _REF_RE.fullmatch(ref) for ref in refs):
        return ()
    return refs


def _missing(request: OracleRequest, *keys: str) -> OracleResult | None:
    absent = [key for key in keys if _fact(request, key) is None]
    if absent:
        return OracleResult(
            status=GateStatus.INCONCLUSIVE,
            reason=f"missing oracle facts: {', '.join(absent)}",
            oracle_id=request.archetype.value,
        )
    return None


def _read_text(request: OracleRequest, ref: str) -> str | None:
    if not request.store.exists(ref):
        return None
    try:
        data = request.store.get(ref)
    except ArtifactStoreError:
        return None
    if len(data) > _MAX_TEXT_BYTES:
        return None
    return data.decode("utf-8", errors="replace")


def _result(
    status: GateStatus,
    reason: str,
    *,
    oracle_id: str,
    evidence_refs: tuple[str, ...] = (),
) -> OracleResult:
    return OracleResult(
        status=status,
        reason=reason,
        evidence_refs=evidence_refs,
        oracle_id=oracle_id,
    )


class ContentMatchOracle:
    oracle_id = "content_match/1.0"
    archetype = OracleArchetype.CONTENT_MATCH

    def evaluate(self, request: OracleRequest) -> OracleResult:
        content_ref = _str_fact(request, "content_ref")
        if content_ref is None:
            content_ref = request.evidence_refs[0] if request.evidence_refs else None
        if content_ref is None or not _REF_RE.fullmatch(content_ref):
            return _result(
                GateStatus.INCONCLUSIVE,
                "content_ref is missing or malformed",
                oracle_id=self.oracle_id,
            )
        if content_ref not in request.evidence_refs:
            return _result(
                GateStatus.FAIL,
                "content_ref is not part of the finding's preserved evidence",
                oracle_id=self.oracle_id,
            )
        expected_sha = _str_fact(request, "expected_sha256")
        expected_text = _str_fact(request, "expected_text")
        if expected_sha is None and expected_text is None:
            return _result(
                GateStatus.INCONCLUSIVE,
                "expected_sha256 or expected_text is required",
                oracle_id=self.oracle_id,
                evidence_refs=(content_ref,),
            )
        if not request.store.exists(content_ref):
            return _result(
                GateStatus.FAIL,
                "content artifact is missing from the store",
                oracle_id=self.oracle_id,
                evidence_refs=(content_ref,),
            )
        if expected_sha is not None:
            if not _REF_RE.fullmatch(expected_sha):
                return _result(
                    GateStatus.FAIL,
                    "expected_sha256 is malformed",
                    oracle_id=self.oracle_id,
                    evidence_refs=(content_ref,),
                )
            try:
                actual = sha256_hex(request.store.get(content_ref))
            except ArtifactStoreError as exc:
                return _result(
                    GateStatus.FAIL,
                    f"content artifact failed integrity verification: {exc}",
                    oracle_id=self.oracle_id,
                    evidence_refs=(content_ref,),
                )
            if actual == expected_sha:
                return _result(
                    GateStatus.PASS,
                    "artifact SHA-256 matches the expected content",
                    oracle_id=self.oracle_id,
                    evidence_refs=(content_ref,),
                )
            return _result(
                GateStatus.FAIL,
                "artifact SHA-256 does not match the expected content",
                oracle_id=self.oracle_id,
                evidence_refs=(content_ref,),
            )

        text = _read_text(request, content_ref)
        if text is None:
            return _result(
                GateStatus.FAIL,
                "content artifact is unreadable or exceeds the oracle text cap",
                oracle_id=self.oracle_id,
                evidence_refs=(content_ref,),
            )
        mode = (_str_fact(request, "match_mode") or "contains").lower()
        assert expected_text is not None
        if mode == "exact":
            matched = text == expected_text
        elif mode == "contains":
            matched = expected_text in text
        else:
            return _result(
                GateStatus.FAIL,
                f"unsupported content match mode: {mode}",
                oracle_id=self.oracle_id,
                evidence_refs=(content_ref,),
            )
        if matched:
            return _result(
                GateStatus.PASS,
                f"content matched in {mode} mode",
                oracle_id=self.oracle_id,
                evidence_refs=(content_ref,),
            )
        return _result(
            GateStatus.FAIL,
            f"content did not match in {mode} mode",
            oracle_id=self.oracle_id,
            evidence_refs=(content_ref,),
        )


class DifferentialStatisticalOracle:
    oracle_id = "differential_statistical/1.0"
    archetype = OracleArchetype.DIFFERENTIAL_STATISTICAL

    def evaluate(self, request: OracleRequest) -> OracleResult:
        missing = _missing(request, "baseline_ref", "probe_refs")
        if missing:
            return missing
        baseline_ref = _str_fact(request, "baseline_ref") or ""
        probes = _refs_fact(request, "probe_refs")
        min_trials = _int_fact(request, "min_trials", 2) or 2
        # Content-addressed storage collapses byte-identical probe responses to
        # one artifact. The independent-trial count therefore comes from the
        # executor's repetition fact; the unique artifacts still prove content.
        repetitions = _int_fact(request, "repetitions", len(probes)) or len(probes)
        if not _REF_RE.fullmatch(baseline_ref) or baseline_ref not in request.evidence_refs:
            return _result(
                GateStatus.FAIL,
                "baseline_ref is malformed or not part of the evidence",
                oracle_id=self.oracle_id,
            )
        if not probes or repetitions < max(2, min_trials):
            return _result(
                GateStatus.INCONCLUSIVE,
                f"differential oracle needs at least {max(2, min_trials)} probe trials",
                oracle_id=self.oracle_id,
                evidence_refs=(baseline_ref, *probes),
            )
        if any(ref not in request.evidence_refs for ref in probes):
            return _result(
                GateStatus.FAIL,
                "a probe artifact is not part of the finding evidence",
                oracle_id=self.oracle_id,
            )
        signal = (_str_fact(request, "signal") or "error_signature").lower()
        refs = (baseline_ref, *probes)

        if signal == "status_diff":
            baseline_status = _int_fact(request, "baseline_status")
            probe_status = _int_fact(request, "probe_status")
            if baseline_status is None or probe_status is None:
                return _result(
                    GateStatus.INCONCLUSIVE,
                    "status_diff requires baseline_status and probe_status",
                    oracle_id=self.oracle_id,
                    evidence_refs=refs,
                )
            if baseline_status != probe_status:
                return _result(
                    GateStatus.PASS,
                    f"status changed from {baseline_status} to {probe_status}",
                    oracle_id=self.oracle_id,
                    evidence_refs=refs,
                )
            return _result(
                GateStatus.FAIL,
                "status did not change between baseline and probe",
                oracle_id=self.oracle_id,
                evidence_refs=refs,
            )

        if signal == "error_signature":
            signature = _str_fact(request, "error_signature")
            if signature is None:
                return _result(
                    GateStatus.INCONCLUSIVE,
                    "error_signature is required for this differential signal",
                    oracle_id=self.oracle_id,
                    evidence_refs=refs,
                )
            baseline = _read_text(request, baseline_ref)
            if baseline is None:
                return _result(
                    GateStatus.FAIL,
                    "baseline artifact is unreadable",
                    oracle_id=self.oracle_id,
                    evidence_refs=refs,
                )
            if signature in baseline:
                return _result(
                    GateStatus.FAIL,
                    "error signature is already present in the baseline",
                    oracle_id=self.oracle_id,
                    evidence_refs=refs,
                )
            for probe in probes:
                text = _read_text(request, probe)
                if text is None:
                    return _result(
                        GateStatus.FAIL,
                        "a probe artifact is unreadable",
                        oracle_id=self.oracle_id,
                        evidence_refs=refs,
                    )
                if signature not in text:
                    return _result(
                        GateStatus.FAIL,
                        "a probe did not reproduce the expected error signature",
                        oracle_id=self.oracle_id,
                        evidence_refs=refs,
                    )
            return _result(
                GateStatus.PASS,
                "error signature appeared in "
                f"{len(probes)} unique probe artifact(s) across {repetitions} independent "
                "trial(s) and not in the baseline",
                oracle_id=self.oracle_id,
                evidence_refs=refs,
            )

        baseline_bytes = _read_bytes(request, baseline_ref)
        if baseline_bytes is None:
            return _result(
                GateStatus.FAIL,
                "baseline artifact is unreadable",
                oracle_id=self.oracle_id,
                evidence_refs=refs,
            )
        baseline_hash = sha256_hex(baseline_bytes)
        for probe in probes:
            probe_bytes = _read_bytes(request, probe)
            if probe_bytes is None:
                return _result(
                    GateStatus.FAIL,
                    "a probe artifact is unreadable",
                    oracle_id=self.oracle_id,
                    evidence_refs=refs,
                )
            if sha256_hex(probe_bytes) == baseline_hash:
                return _result(
                    GateStatus.FAIL,
                    "a probe is byte-identical to the baseline",
                    oracle_id=self.oracle_id,
                    evidence_refs=refs,
                )
        return _result(
            GateStatus.PASS,
            f"{len(probes)} unique probe artifact(s) across {repetitions} trial(s) "
            "differ from the baseline",
            oracle_id=self.oracle_id,
            evidence_refs=refs,
        )


def _read_bytes(request: OracleRequest, ref: str) -> bytes | None:
    if not request.store.exists(ref):
        return None
    try:
        return request.store.get(ref)
    except ArtifactStoreError:
        return None


class ComponentMatchOracle:
    oracle_id = "component_match/1.0"
    archetype = OracleArchetype.COMPONENT_MATCH

    def evaluate(self, request: OracleRequest) -> OracleResult:
        missing = _missing(request, "component", "version", "affected_min", "reachability_ref")
        if missing:
            return missing
        component = _str_fact(request, "component") or ""
        version_text = _str_fact(request, "version") or ""
        minimum_text = _str_fact(request, "affected_min") or ""
        maximum_text = _str_fact(request, "affected_max")
        reachability_ref = _str_fact(request, "reachability_ref") or ""
        if not _bool_fact(request, "reachability_confirmed"):
            return _result(
                GateStatus.INCONCLUSIVE,
                "component match requires confirmed reachability, not just a version",
                oracle_id=self.oracle_id,
            )
        if reachability_ref not in request.evidence_refs or not _REF_RE.fullmatch(reachability_ref):
            return _result(
                GateStatus.FAIL,
                "reachability_ref is malformed or not part of the evidence",
                oracle_id=self.oracle_id,
            )
        try:
            version = Version(version_text)
            minimum = Version(minimum_text)
            maximum = Version(maximum_text) if maximum_text else None
        except InvalidVersion:
            return _result(
                GateStatus.INCONCLUSIVE,
                "component or affected version is not parseable",
                oracle_id=self.oracle_id,
                evidence_refs=(reachability_ref,),
            )
        if version < minimum or (maximum is not None and version > maximum):
            return _result(
                GateStatus.FAIL,
                f"{component} {version} is outside the affected range",
                oracle_id=self.oracle_id,
                evidence_refs=(reachability_ref,),
            )
        if not request.store.exists(reachability_ref):
            return _result(
                GateStatus.FAIL,
                "reachability artifact is missing",
                oracle_id=self.oracle_id,
                evidence_refs=(reachability_ref,),
            )
        return _result(
            GateStatus.PASS,
            f"{component} {version} is in the affected range and reachability is confirmed",
            oracle_id=self.oracle_id,
            evidence_refs=(reachability_ref,),
        )


class CryptographicProofOracle:
    oracle_id = "cryptographic_proof/1.0"
    archetype = OracleArchetype.CRYPTOGRAPHIC_PROOF

    def evaluate(self, request: OracleRequest) -> OracleResult:
        proof_type = _str_fact(request, "proof_type")
        if proof_type == "artifact_sha256":
            missing = _missing(request, "artifact_ref", "expected_sha256")
            if missing:
                return missing
            ref = _str_fact(request, "artifact_ref") or ""
            expected = _str_fact(request, "expected_sha256") or ""
            if ref not in request.evidence_refs or not _REF_RE.fullmatch(ref):
                return _result(
                    GateStatus.FAIL,
                    "artifact_ref is malformed or not part of the evidence",
                    oracle_id=self.oracle_id,
                )
            data = _read_bytes(request, ref)
            if data is None:
                return _result(
                    GateStatus.FAIL,
                    "artifact is missing or unreadable",
                    oracle_id=self.oracle_id,
                    evidence_refs=(ref,),
                )
            if not _REF_RE.fullmatch(expected):
                return _result(
                    GateStatus.FAIL,
                    "expected_sha256 is malformed",
                    oracle_id=self.oracle_id,
                    evidence_refs=(ref,),
                )
            if sha256_hex(data) == expected:
                return _result(
                    GateStatus.PASS,
                    "deterministic SHA-256 verification passed",
                    oracle_id=self.oracle_id,
                    evidence_refs=(ref,),
                )
            return _result(
                GateStatus.FAIL,
                "deterministic SHA-256 verification failed",
                oracle_id=self.oracle_id,
                evidence_refs=(ref,),
            )
        if proof_type == "signature_verified":
            missing = _missing(request, "verifier", "verification_ref")
            if missing:
                return missing
            verifier = _str_fact(request, "verifier") or ""
            ref = _str_fact(request, "verification_ref") or ""
            if verifier not in _ALLOWED_VERIFIERS:
                return _result(
                    GateStatus.INCONCLUSIVE,
                    f"verifier {verifier!r} is not in the reviewed verifier allowlist",
                    oracle_id=self.oracle_id,
                )
            if not _bool_fact(request, "verifier_result"):
                return _result(
                    GateStatus.FAIL,
                    "the deterministic verifier did not report success",
                    oracle_id=self.oracle_id,
                    evidence_refs=(ref,),
                )
            if ref not in request.evidence_refs or not request.store.exists(ref):
                return _result(
                    GateStatus.FAIL,
                    "verification artifact is missing or outside the evidence",
                    oracle_id=self.oracle_id,
                )
            return _result(
                GateStatus.PASS,
                f"reviewed verifier {verifier} reported success",
                oracle_id=self.oracle_id,
                evidence_refs=(ref,),
            )
        return _result(
            GateStatus.INCONCLUSIVE,
            "unsupported cryptographic proof type",
            oracle_id=self.oracle_id,
        )


class StateChangeAuthzOracle:
    oracle_id = "state_change_authz/1.0"
    archetype = OracleArchetype.STATE_CHANGE_AUTHZ

    def evaluate(self, request: OracleRequest) -> OracleResult:
        missing = _missing(request, "before_state_ref", "after_state_ref", "identity")
        if missing:
            return missing
        before = _str_fact(request, "before_state_ref") or ""
        after = _str_fact(request, "after_state_ref") or ""
        identity = (_str_fact(request, "identity") or "").lower()
        if before not in request.evidence_refs or after not in request.evidence_refs:
            return _result(
                GateStatus.FAIL,
                "state artifacts must be part of the finding evidence",
                oracle_id=self.oracle_id,
            )
        if identity not in {"unauthorized", "lower_privilege", "unauthenticated"}:
            return _result(
                GateStatus.FAIL,
                "state change was not demonstrated from an unauthorized identity",
                oracle_id=self.oracle_id,
            )
        if not _bool_fact(request, "state_changed"):
            return _result(
                GateStatus.FAIL,
                "protected state change was not observed",
                oracle_id=self.oracle_id,
                evidence_refs=(before, after),
            )
        before_bytes = _read_bytes(request, before)
        after_bytes = _read_bytes(request, after)
        if before_bytes is None or after_bytes is None:
            return _result(
                GateStatus.FAIL,
                "state artifact is missing or unreadable",
                oracle_id=self.oracle_id,
                evidence_refs=(before, after),
            )
        if before_bytes == after_bytes:
            return _result(
                GateStatus.FAIL,
                "state artifacts are identical",
                oracle_id=self.oracle_id,
                evidence_refs=(before, after),
            )
        return _result(
            GateStatus.PASS,
            "protected state changed from an unauthorized identity",
            oracle_id=self.oracle_id,
            evidence_refs=(before, after),
        )


class OutOfBandOracle:
    oracle_id = "out_of_band/1.0"
    archetype = OracleArchetype.OUT_OF_BAND

    def evaluate(self, request: OracleRequest) -> OracleResult:
        missing = _missing(request, "callback_token", "callback_ref", "request_ref")
        if missing:
            return missing
        token = _str_fact(request, "callback_token") or ""
        callback_ref = _str_fact(request, "callback_ref") or ""
        request_ref = _str_fact(request, "request_ref") or ""
        window = _int_fact(request, "window_seconds")
        if callback_ref not in request.evidence_refs or request_ref not in request.evidence_refs:
            return _result(
                GateStatus.FAIL,
                "callback and request artifacts must be part of the finding evidence",
                oracle_id=self.oracle_id,
            )
        if window is None or not 1 <= window <= 3600:
            return _result(
                GateStatus.INCONCLUSIVE,
                "window_seconds must be between 1 and 3600",
                oracle_id=self.oracle_id,
            )
        if not _bool_fact(request, "callback_within_window"):
            return _result(
                GateStatus.FAIL,
                "callback arrived outside the declared correlation window",
                oracle_id=self.oracle_id,
                evidence_refs=(callback_ref, request_ref),
            )
        callback = _read_text(request, callback_ref)
        request_text = _read_text(request, request_ref)
        if callback is None or request_text is None:
            return _result(
                GateStatus.FAIL,
                "callback or request artifact is unreadable",
                oracle_id=self.oracle_id,
                evidence_refs=(callback_ref, request_ref),
            )
        if token not in request_text:
            return _result(
                GateStatus.FAIL,
                "correlation token is absent from the request artifact",
                oracle_id=self.oracle_id,
                evidence_refs=(callback_ref, request_ref),
            )
        if token not in callback:
            return _result(
                GateStatus.FAIL,
                "correlation token is absent from the callback artifact",
                oracle_id=self.oracle_id,
                evidence_refs=(callback_ref, request_ref),
            )
        return _result(
            GateStatus.PASS,
            "unique callback token correlated inside the declared window",
            oracle_id=self.oracle_id,
            evidence_refs=(callback_ref, request_ref),
        )


class GraphReachabilityOracle:
    oracle_id = "graph_reachability/1.0"
    archetype = OracleArchetype.GRAPH_REACHABILITY

    def evaluate(self, request: OracleRequest) -> OracleResult:
        missing = _missing(request, "required_edges", "confirmed_edges", "edge_refs")
        if missing:
            return missing
        required = _int_fact(request, "required_edges")
        confirmed = _int_fact(request, "confirmed_edges")
        inferred = _int_fact(request, "inferred_edges", 0) or 0
        refs = _refs_fact(request, "edge_refs")
        if required is None or required < 1 or confirmed is None:
            return _result(
                GateStatus.INCONCLUSIVE,
                "edge counts are missing or invalid",
                oracle_id=self.oracle_id,
            )
        if inferred > 0:
            return _result(
                GateStatus.INCONCLUSIVE,
                "path includes inferred edges; each edge must be empirically confirmed",
                oracle_id=self.oracle_id,
                evidence_refs=refs,
            )
        if confirmed != required:
            return _result(
                GateStatus.FAIL,
                f"only {confirmed} of {required} path edges are confirmed",
                oracle_id=self.oracle_id,
                evidence_refs=refs,
            )
        if len(refs) != required or any(ref not in request.evidence_refs for ref in refs):
            return _result(
                GateStatus.FAIL,
                "edge evidence references do not cover every confirmed edge",
                oracle_id=self.oracle_id,
                evidence_refs=refs,
            )
        if any(not request.store.exists(ref) for ref in refs):
            return _result(
                GateStatus.FAIL,
                "an edge evidence artifact is missing",
                oracle_id=self.oracle_id,
                evidence_refs=refs,
            )
        return _result(
            GateStatus.PASS,
            f"all {required} path edges are empirically confirmed",
            oracle_id=self.oracle_id,
            evidence_refs=refs,
        )


class SideEffectExecutionOracle:
    oracle_id = "side_effect_execution/1.0"
    archetype = OracleArchetype.SIDE_EFFECT_EXECUTION

    def evaluate(self, request: OracleRequest) -> OracleResult:
        missing = _missing(request, "execution_marker_ref", "expected_marker")
        if missing:
            return missing
        ref = _str_fact(request, "execution_marker_ref") or ""
        marker = _str_fact(request, "expected_marker") or ""
        if not _bool_fact(request, "controlled_environment"):
            return _result(
                GateStatus.FAIL,
                "side-effect proof requires a tester-controlled environment",
                oracle_id=self.oracle_id,
                evidence_refs=(ref,),
            )
        if ref not in request.evidence_refs:
            return _result(
                GateStatus.FAIL,
                "execution marker artifact is outside the finding evidence",
                oracle_id=self.oracle_id,
                evidence_refs=(ref,),
            )
        text = _read_text(request, ref)
        if text is None:
            return _result(
                GateStatus.FAIL,
                "execution marker artifact is unreadable",
                oracle_id=self.oracle_id,
                evidence_refs=(ref,),
            )
        if marker in text:
            return _result(
                GateStatus.PASS,
                "controlled execution marker was observed",
                oracle_id=self.oracle_id,
                evidence_refs=(ref,),
            )
        return _result(
            GateStatus.FAIL,
            "controlled execution marker was not observed",
            oracle_id=self.oracle_id,
            evidence_refs=(ref,),
        )


class CrashPoVOracle:
    oracle_id = "crash_pov/1.0"
    archetype = OracleArchetype.CRASH_POV

    def evaluate(self, request: OracleRequest) -> OracleResult:
        missing = _missing(request, "crash_signature", "crash_refs")
        if missing:
            return missing
        signature = _str_fact(request, "crash_signature") or ""
        refs = _refs_fact(request, "crash_refs")
        replays = _int_fact(request, "replays", 0) or 0
        if replays < 2:
            return _result(
                GateStatus.INCONCLUSIVE,
                "crash proof requires at least two recorded replays",
                oracle_id=self.oracle_id,
                evidence_refs=refs,
            )
        if not _bool_fact(request, "replayable"):
            return _result(
                GateStatus.FAIL,
                "crash was not replayable",
                oracle_id=self.oracle_id,
                evidence_refs=refs,
            )
        if len(refs) < 2 or any(ref not in request.evidence_refs for ref in refs):
            return _result(
                GateStatus.FAIL,
                "crash evidence references are incomplete",
                oracle_id=self.oracle_id,
                evidence_refs=refs,
            )
        for ref in refs:
            text = _read_text(request, ref)
            if text is None:
                return _result(
                    GateStatus.FAIL,
                    "a crash artifact is unreadable",
                    oracle_id=self.oracle_id,
                    evidence_refs=refs,
                )
            if signature not in text:
                return _result(
                    GateStatus.FAIL,
                    "a replay did not reproduce the crash signature",
                    oracle_id=self.oracle_id,
                    evidence_refs=refs,
                )
        return _result(
            GateStatus.PASS,
            f"crash signature reproduced in {len(refs)} replays",
            oracle_id=self.oracle_id,
            evidence_refs=refs,
        )


class AvailabilityBoundedOracle:
    oracle_id = "availability_bounded/1.0"
    archetype = OracleArchetype.AVAILABILITY_BOUNDED

    def evaluate(self, request: OracleRequest) -> OracleResult:
        missing = _missing(request, "baseline_ref", "measurement_ref", "impact_threshold")
        if missing:
            return missing
        baseline = _str_fact(request, "baseline_ref") or ""
        measurement = _str_fact(request, "measurement_ref") or ""
        threshold = _float_fact(request, "impact_threshold")
        delta = _float_fact(request, "measured_delta")
        if not _bool_fact(request, "bounded") or not _bool_fact(request, "reversible"):
            return _result(
                GateStatus.FAIL,
                "availability proof must be bounded and reversible",
                oracle_id=self.oracle_id,
                evidence_refs=(baseline, measurement),
            )
        if threshold is None or delta is None or threshold <= 0:
            return _result(
                GateStatus.INCONCLUSIVE,
                "impact_threshold and measured_delta are required",
                oracle_id=self.oracle_id,
                evidence_refs=(baseline, measurement),
            )
        if baseline not in request.evidence_refs or measurement not in request.evidence_refs:
            return _result(
                GateStatus.FAIL,
                "availability evidence is outside the finding",
                oracle_id=self.oracle_id,
            )
        if delta < threshold:
            return _result(
                GateStatus.FAIL,
                "measured impact did not exceed the declared threshold",
                oracle_id=self.oracle_id,
                evidence_refs=(baseline, measurement),
            )
        return _result(
            GateStatus.PASS,
            "bounded, reversible availability impact exceeded the declared threshold",
            oracle_id=self.oracle_id,
            evidence_refs=(baseline, measurement),
        )


DEFAULT_ORACLES: tuple[Oracle, ...] = (
    ContentMatchOracle(),
    DifferentialStatisticalOracle(),
    ComponentMatchOracle(),
    CryptographicProofOracle(),
    StateChangeAuthzOracle(),
    OutOfBandOracle(),
    GraphReachabilityOracle(),
    SideEffectExecutionOracle(),
    CrashPoVOracle(),
    AvailabilityBoundedOracle(),
)


class OracleRegistry:
    """Closed registry keyed by the fixed proof archetype."""

    def __init__(self, oracles: tuple[Oracle, ...] = DEFAULT_ORACLES) -> None:
        index: dict[OracleArchetype, Oracle] = {}
        for oracle in oracles:
            if oracle.archetype in index:
                raise ValueError(f"duplicate oracle for {oracle.archetype}")
            index[oracle.archetype] = oracle
        self._oracles = index

    def get(self, archetype: OracleArchetype) -> Oracle | None:
        return self._oracles.get(archetype)

    def evaluate(self, request: OracleRequest) -> OracleResult:
        oracle = self.get(request.archetype)
        if oracle is None:
            return OracleResult(
                status=GateStatus.INCONCLUSIVE,
                reason=f"no oracle registered for {request.archetype.value}",
                oracle_id="unregistered",
            )
        return oracle.evaluate(request)


DEFAULT_ORACLE_REGISTRY = OracleRegistry()
