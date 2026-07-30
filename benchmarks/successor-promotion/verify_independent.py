from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any, Dict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HEX64 = re.compile(r"^[0-9a-f]{64}$")
APPRAISAL_SCHEMA = "openline.eval_airlock.appraisal_receipt.v0.3"
APPRAISAL_TYPE = "eval_airlock_appraisal"


def load(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sha256_json(obj: Any) -> str:
    return hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()


def norm_actor(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return re.sub(r"[^a-z0-9]+", "", value.strip().lower())


def is_hash(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    raw = value.strip().lower()
    if raw.startswith("sha256:"):
        raw = raw.split(":", 1)[1]
    return bool(HEX64.fullmatch(raw))


def nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def finite_number(value: Any) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(float(value))


def decision_chain_invalid(raw: Any) -> bool:
    if raw is None:
        return False
    if not isinstance(raw, str) or not raw.strip():
        return False
    prev = None
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            return True
        if not isinstance(row, dict):
            return True
        if row.get("parent_hash") != prev:
            return True
        expected = sha256_json({k: v for k, v in row.items() if k != "receipt_hash"})
        if row.get("receipt_hash") != expected:
            return True
        prev = row.get("receipt_hash")
    return False


def verify_materialized_appraisal(profile: Dict[str, Any], case: Dict[str, Any], appraisal: Dict[str, Any]) -> list[str]:
    digest = appraisal.get("appraisal_receipt_hash")
    if not is_hash(digest):
        return []
    document = case.get("appraisal_receipt_document")
    if document is None:
        return ["appraisal_receipt_not_found"]
    if not isinstance(document, dict):
        return ["appraisal_receipt_shape_mismatch"]
    try:
        if sha256_json(document) != digest:
            return ["appraisal_receipt_hash_mismatch"]
    except (TypeError, ValueError, OverflowError):
        return ["appraisal_receipt_unreadable"]

    base_keys = {"schema", "receipt_type", "witness", "appraisal", "payload_hash"}
    if not base_keys.issubset(document) or (set(document) - (base_keys | {"signature"})):
        return ["appraisal_receipt_shape_mismatch"]
    if document.get("schema") != APPRAISAL_SCHEMA:
        return ["appraisal_receipt_schema_mismatch"]
    if document.get("receipt_type") != APPRAISAL_TYPE:
        return ["appraisal_receipt_type_mismatch"]
    expected_witness = {"evaluator_id": appraisal.get("evaluator_id"), "evaluator_hash": appraisal.get("evaluator_hash")}
    if document.get("witness") != expected_witness:
        return ["appraisal_receipt_witness_mismatch"]
    expected_claim = {k: v for k, v in appraisal.items() if k != "appraisal_receipt_hash"}
    if document.get("appraisal") != expected_claim:
        return ["appraisal_receipt_payload_mismatch"]

    if not profile.get("require_signed_appraisal_receipt"):
        return []
    signature = document.get("signature")
    if not isinstance(signature, dict):
        return ["appraisal_signature_missing"]
    if set(signature) != {"algorithm", "public_key", "value"}:
        return ["appraisal_signature_shape_mismatch"]
    if signature.get("algorithm") != "Ed25519":
        return ["appraisal_signature_algorithm_mismatch"]
    public_key = signature.get("public_key")
    if not isinstance(public_key, str) or public_key.lower() != str(profile.get("expected_evaluator_public_key", "")).lower():
        return ["appraisal_signer_not_pinned"]
    body = {k: document[k] for k in ("schema", "receipt_type", "witness", "appraisal")}
    try:
        canonical_bytes = canonical(body).encode("utf-8")
    except (TypeError, ValueError, OverflowError):
        return ["appraisal_receipt_unreadable"]
    if document.get("payload_hash") != hashlib.sha256(canonical_bytes).hexdigest():
        return ["appraisal_payload_hash_mismatch"]
    try:
        public_raw = bytes.fromhex(public_key)
        signature_raw = bytes.fromhex(str(signature.get("value", "")))
        if len(public_raw) != 32 or len(signature_raw) != 64:
            return ["appraisal_signature_invalid"]
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature_raw, canonical_bytes)
    except (ValueError, TypeError, InvalidSignature):
        return ["appraisal_signature_invalid"]
    return []


def evaluate(profile: Dict[str, Any], case: Dict[str, Any]) -> Dict[str, Any]:
    p = case["proposal"]
    a = case["appraisal"]
    q: list[str] = []
    r: list[str] = []

    if decision_chain_invalid(case.get("preexisting_decision_chain")):
        q.append("invalid_destination_receipt_chain")

    now = case.get("now")
    if not finite_number(now):
        q.append("invalid_receiver_time")

    for name in ("proposal_id", "proposer_id", "source_version_id", "successor_version_id"):
        if not nonempty_string(p.get(name)):
            q.append(f"invalid_{name}")
    if not isinstance(p.get("change_summary"), str): q.append("invalid_change_summary")
    if not is_hash(p.get("source_version_hash")): q.append("invalid_source_version_hash")
    if not is_hash(p.get("successor_version_hash")): q.append("invalid_successor_version_hash")
    if not finite_number(p.get("created_at")): q.append("invalid_proposal_timestamp")
    if case["current_version_hash"] != p.get("source_version_hash"): q.append("source_version_not_current")
    if p.get("source_version_hash") == p.get("successor_version_hash"): q.append("successor_has_no_version_delta")

    if a is None:
        q.append("missing_eval_airlock_appraisal")
    else:
        for name in ("baseline_score", "candidate_score", "issued_at"):
            if not finite_number(a.get(name)): q.append(f"invalid_{name}")
        critical = a.get("critical_failures")
        if isinstance(critical, bool) or not isinstance(critical, int) or critical < 0: q.append("invalid_critical_failures")
        if not isinstance(a.get("evaluation_complete"), bool): q.append("invalid_evaluation_complete")
        if not isinstance(a.get("evidence_status"), str): q.append("invalid_evidence_status")
        if profile["require_external_appraisal_receipt"] and not is_hash(a.get("appraisal_receipt_hash")): q.append("missing_or_invalid_appraisal_receipt")
        if a.get("source_version_hash") != p.get("source_version_hash"): q.append("appraisal_wrong_source_version")
        if a.get("successor_version_hash") != p.get("successor_version_hash"): q.append("appraisal_wrong_successor_version")
        if profile["require_relation_history"] and not is_hash(a.get("relation_history_hash")): q.append("missing_relation_history")
        if profile.get("require_materialized_appraisal_receipt") and is_hash(a.get("appraisal_receipt_hash")):
            q.extend(verify_materialized_appraisal(profile, case, a))
        if norm_actor(a.get("evaluator_id")) and norm_actor(a.get("evaluator_id")) == norm_actor(p.get("proposer_id")): q.append("successor_proposer_is_evaluator")
        if norm_actor(a.get("benchmark_owner")) and norm_actor(a.get("benchmark_owner")) == norm_actor(p.get("proposer_id")): q.append("successor_proposer_owns_benchmark")
        if a.get("evaluator_id") != profile["expected_evaluator_id"]: q.append("evaluator_id_not_frozen")
        if a.get("evaluator_hash") != profile["expected_evaluator_hash"]: q.append("evaluator_hash_not_frozen")
        if a.get("benchmark_id") != profile["expected_benchmark_id"]: q.append("benchmark_id_not_frozen")
        if a.get("benchmark_version") != profile["expected_benchmark_version"]: q.append("benchmark_version_not_frozen")
        if a.get("benchmark_owner") != profile["expected_benchmark_owner"]: q.append("benchmark_owner_not_frozen")
        if a.get("heldout_set_hash") != profile["expected_heldout_set_hash"]: q.append("heldout_set_not_frozen")
        if a.get("policy_hash") != profile["expected_policy_hash"]: q.append("appraisal_policy_not_frozen")
        if "invalid_receiver_time" not in q and "invalid_issued_at" not in q:
            age = float(now) - float(a["issued_at"])
            if age < 0: q.append("appraisal_from_future")
            elif age > float(profile["max_appraisal_age_seconds"]): q.append("appraisal_stale")
        if not q:
            if a.get("evaluation_complete") is not True: q.append("evaluation_incomplete")
            if a.get("evidence_status") != "SUPPORTED": q.append("appraisal_not_supported")
        if not q:
            delta = a["candidate_score"] - a["baseline_score"]
            if not math.isfinite(delta):
                q.append("nonfinite_heldout_delta")
            else:
                if a["critical_failures"] > int(profile["max_critical_failures"]): r.append("critical_failure_detected")
                if delta < float(profile["min_heldout_delta"]): r.append("heldout_delta_regressed")
                if a["candidate_score"] < float(profile["min_candidate_score"]): r.append("candidate_score_below_floor")

    q = sorted(set(q)); r = sorted(set(r))
    decision = "QUARANTINE" if q else ("REJECT" if r else "PROMOTE")
    return {"decision": decision, "quarantine_flags": q, "reject_flags": r}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    root = Path(__file__).resolve().parent
    profile = load(root / "FROZEN_PROFILE.json")
    doc = load(root / "FROZEN_CASES.json")
    report_path = root / "BENCHMARK_REPORT.json"
    report = load(report_path)
    errors = []

    try:
        public_raw = bytes.fromhex(profile["expected_evaluator_public_key"])
        if len(public_raw) != 32:
            raise ValueError
        if hashlib.sha256(public_raw).hexdigest() != profile["expected_evaluator_hash"]:
            errors.append("evaluator_key_fingerprint_mismatch")
    except (KeyError, TypeError, ValueError):
        errors.append("invalid_evaluator_key_pin")

    report_rows = {row["case_id"]: row for row in report["cases"]}
    for case in doc["cases"]:
        expected = evaluate(profile, case)
        frozen = {
            "decision": case["expected_decision"],
            "quarantine_flags": case["expected_quarantine_flags"],
            "reject_flags": case["expected_reject_flags"],
        }
        if expected != frozen:
            errors.append(f"frozen_expectation_mismatch:{case['case_id']}:{expected!r}:{frozen!r}")
        row = report_rows.get(case["case_id"])
        if row is None:
            errors.append(f"report_missing_case:{case['case_id']}")
        else:
            actual = {"decision": row["decision"], "quarantine_flags": row["quarantine_flags"], "reject_flags": row["reject_flags"]}
            if actual != expected:
                errors.append(f"report_result_mismatch:{case['case_id']}")
            if (row.get("promotion_intent") is not None) != (row.get("decision") == "PROMOTE"):
                errors.append(f"promotion_intent_shape_mismatch:{case['case_id']}")
    if report.get("case_count") != len(doc["cases"]):
        errors.append("report_case_count_mismatch")
    result = {
        "schema": "openline.swarm_improvement_gate.successor_independent_verification.v0.3",
        "independent_of_olp_swarm_gate_imports": True,
        "cryptographic_verifier": "cryptography.Ed25519PublicKey",
        "profile_sha256": sha256(root / "FROZEN_PROFILE.json"),
        "cases_sha256": sha256(root / "FROZEN_CASES.json"),
        "report_sha256": sha256(report_path),
        "case_count": len(doc["cases"]),
        "errors": errors,
        "valid": not errors,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
