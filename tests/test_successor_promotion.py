import hashlib
import json
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
import inspect

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_swarm_gate import (
    EvalAirlockAppraisal,
    SuccessorProposal,
    SuccessorPromotionGate,
    SuccessorPromotionPolicy,
    materialize_appraisal_receipt,
    evaluator_key_fingerprint,
    public_key_hex,
)
from olp_swarm_gate.appraisal_receipts import build_appraisal_receipt_document, appraisal_receipt_digest, unsigned_appraisal_receipt_body
from olp_swarm_gate.successor_benchmark import run_frozen_benchmark
from olp_swarm_gate.receipts import verify_chain


def h(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


TEST_EVALUATOR_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("91" * 32))
TEST_ATTACKER_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("92" * 32))
TEST_EVALUATOR_PUBLIC_KEY = public_key_hex(TEST_EVALUATOR_KEY)
TEST_EVALUATOR_HASH = evaluator_key_fingerprint(TEST_EVALUATOR_PUBLIC_KEY)


def policy(tmp_path: Path, **overrides):
    data = dict(
        receipt_path=str(tmp_path / "promotion.jsonl"),
        appraisal_receipt_dir=str(tmp_path / "appraisals"),
        expected_evaluator_id="openline-eval-airlock",
        expected_evaluator_hash=TEST_EVALUATOR_HASH,
        expected_evaluator_public_key=TEST_EVALUATOR_PUBLIC_KEY,
        expected_benchmark_id="successor-promotion",
        expected_benchmark_version="v1",
        expected_benchmark_owner="receiver",
        expected_heldout_set_hash=h("heldout"),
        expected_policy_hash=h("policy"),
        min_heldout_delta=0.01,
        min_candidate_score=0.75,
        max_critical_failures=0,
        max_appraisal_age_seconds=3600,
    )
    data.update(overrides)
    return SuccessorPromotionPolicy(**data)


def proposal(**overrides):
    data = dict(
        proposal_id="p1",
        proposer_id="version-a-agent",
        source_version_id="A",
        source_version_hash=h("A"),
        successor_version_id="B",
        successor_version_hash=h("B"),
        change_summary="B claims improvement",
        created_at=1000.0,
    )
    data.update(overrides)
    return SuccessorProposal(**data)


def appraisal(pol: SuccessorPromotionPolicy, prop: SuccessorProposal, *, materialize=True, **overrides):
    data = dict(
        appraisal_receipt_hash="",
        evaluator_id=pol.expected_evaluator_id,
        evaluator_hash=pol.expected_evaluator_hash,
        benchmark_id=pol.expected_benchmark_id,
        benchmark_version=pol.expected_benchmark_version,
        benchmark_owner=pol.expected_benchmark_owner,
        heldout_set_hash=pol.expected_heldout_set_hash,
        policy_hash=pol.expected_policy_hash,
        relation_history_hash=h("relations"),
        source_version_hash=prop.source_version_hash,
        successor_version_hash=prop.successor_version_hash,
        baseline_score=0.72,
        candidate_score=0.82,
        critical_failures=0,
        evaluation_complete=True,
        evidence_status="SUPPORTED",
        issued_at=1900.0,
    )
    data.update(overrides)
    app = EvalAirlockAppraisal(**data)
    return materialize_appraisal_receipt(app, pol.appraisal_receipt_dir, signing_key=TEST_EVALUATOR_KEY) if materialize else app


def evaluate(tmp_path: Path, prop=None, app_overrides=None, pol_overrides=None, current=None, now=2000.0, metadata=None):
    pol = policy(tmp_path, **(pol_overrides or {}))
    prop = prop or proposal()
    app = appraisal(pol, prop, **(app_overrides or {}))
    gate = SuccessorPromotionGate(pol)
    return gate.evaluate(proposal=prop, appraisal=app, current_version_hash=current or prop.source_version_hash, now=now, metadata=metadata)


def test_valid_successor_promotes_and_emits_exact_intent(tmp_path):
    receipt = evaluate(tmp_path)
    assert receipt["decision"] == "PROMOTE"
    assert receipt["quarantine_flags"] == []
    assert receipt["reject_flags"] == []
    intent = receipt["promotion_intent"]
    assert intent["source_version_hash"] == h("A")
    assert intent["successor_version_hash"] == h("B")
    assert intent["enforcement"] == "NOT_EXECUTED_BY_SWARM_IMPROVEMENT_GATE"
    assert intent["next_enforcer"] == "openline-receipt-gate/verified-commit"
    assert receipt["gate_assertions"]["promotion_requires_receiver_pinned_evaluator_signature"] is True
    assert verify_chain(tmp_path / "promotion.jsonl")["valid"] is True


def test_arbitrary_hash_without_materialized_receipt_cannot_promote(tmp_path):
    pol = policy(tmp_path)
    prop = proposal()
    app = appraisal(pol, prop, materialize=False, appraisal_receipt_hash=h("invented"))
    receipt = SuccessorPromotionGate(pol).evaluate(proposal=prop, appraisal=app, current_version_hash=prop.source_version_hash, now=2000.0)
    assert receipt["decision"] == "QUARANTINE"
    assert receipt["quarantine_flags"] == ["appraisal_receipt_not_found"]
    assert receipt["promotion_intent"] is None


def test_same_receipt_hash_cannot_launder_changed_score(tmp_path):
    pol = policy(tmp_path)
    prop = proposal()
    bound = appraisal(pol, prop)
    tampered = replace(bound, candidate_score=0.99)
    receipt = SuccessorPromotionGate(pol).evaluate(proposal=prop, appraisal=tampered, current_version_hash=prop.source_version_hash, now=2000.0)
    assert receipt["decision"] == "QUARANTINE"
    assert receipt["quarantine_flags"] == ["appraisal_receipt_payload_mismatch"]
    assert receipt["promotion_intent"] is None


def test_materialized_receipt_tamper_is_detected(tmp_path):
    pol = policy(tmp_path)
    prop = proposal()
    bound = appraisal(pol, prop)
    path = Path(pol.appraisal_receipt_dir) / f"{bound.appraisal_receipt_hash}.json"
    doc = json.loads(path.read_text())
    doc["appraisal"]["candidate_score"] = 0.99
    path.write_text(json.dumps(doc), encoding="utf-8")
    receipt = SuccessorPromotionGate(pol).evaluate(proposal=prop, appraisal=bound, current_version_hash=prop.source_version_hash, now=2000.0)
    assert receipt["decision"] == "QUARANTINE"
    assert receipt["quarantine_flags"] == ["appraisal_receipt_hash_mismatch"]


def test_invalid_existing_decision_chain_fails_closed_and_is_not_extended(tmp_path):
    pol = policy(tmp_path)
    prop = proposal()
    app = appraisal(pol, prop)
    decision_path = Path(pol.receipt_path)
    decision_path.write_text("{not-json\n", encoding="utf-8")
    before = decision_path.read_bytes()
    receipt = SuccessorPromotionGate(pol).evaluate(proposal=prop, appraisal=app, current_version_hash=prop.source_version_hash, now=2000.0)
    assert receipt["decision"] == "QUARANTINE"
    assert receipt["quarantine_flags"] == ["invalid_destination_receipt_chain"]
    assert receipt["promotion_intent"] is None
    assert receipt["receipt_persisted"] is False
    assert decision_path.read_bytes() == before


def test_nonpromote_never_emits_actionable_promotion_intent(tmp_path):
    receipt = evaluate(tmp_path, app_overrides={"issued_at": 0.0}, now=4000.0)
    assert receipt["decision"] == "QUARANTINE"
    assert receipt["promotion_intent"] is None


def test_caller_metadata_cannot_overwrite_gate_assertions(tmp_path):
    receipt = evaluate(tmp_path, metadata={"promotion_requires_receiver_pinned_evaluator_signature": False, "raw_successor_payload_stored": True})
    assert receipt["decision"] == "PROMOTE"
    assert receipt["metadata"]["promotion_requires_receiver_pinned_evaluator_signature"] is False
    assert receipt["gate_assertions"]["promotion_requires_receiver_pinned_evaluator_signature"] is True
    assert receipt["gate_assertions"]["raw_successor_payload_stored"] is False


def test_successor_cannot_be_its_own_evaluator(tmp_path):
    prop = proposal(proposer_id="openline-eval-airlock")
    receipt = evaluate(tmp_path, prop=prop)
    assert receipt["decision"] == "QUARANTINE"
    assert receipt["quarantine_flags"] == ["successor_proposer_is_evaluator"]


def test_evaluator_hash_mismatch_quarantines(tmp_path):
    receipt = evaluate(tmp_path, app_overrides={"evaluator_hash": h("changed")})
    assert receipt["decision"] == "QUARANTINE"
    assert "evaluator_hash_not_frozen" in receipt["quarantine_flags"]


def test_wrong_heldout_set_quarantines(tmp_path):
    receipt = evaluate(tmp_path, app_overrides={"heldout_set_hash": h("visible")})
    assert receipt["decision"] == "QUARANTINE"
    assert "heldout_set_not_frozen" in receipt["quarantine_flags"]


def test_wrong_policy_hash_quarantines(tmp_path):
    receipt = evaluate(tmp_path, app_overrides={"policy_hash": h("candidate-policy")})
    assert receipt["decision"] == "QUARANTINE"
    assert "appraisal_policy_not_frozen" in receipt["quarantine_flags"]


def test_replayed_appraisal_for_other_successor_quarantines(tmp_path):
    receipt = evaluate(tmp_path, app_overrides={"successor_version_hash": h("C")})
    assert receipt["decision"] == "QUARANTINE"
    assert "appraisal_wrong_successor_version" in receipt["quarantine_flags"]


def test_stale_source_version_quarantines(tmp_path):
    prop = proposal(source_version_hash=h("stale-A"))
    receipt = evaluate(tmp_path, prop=prop, current=h("A"))
    assert receipt["decision"] == "QUARANTINE"
    assert "source_version_not_current" in receipt["quarantine_flags"]


def test_stale_appraisal_quarantines(tmp_path):
    receipt = evaluate(tmp_path, app_overrides={"issued_at": 0.0}, now=4000.0)
    assert receipt["decision"] == "QUARANTINE"
    assert "appraisal_stale" in receipt["quarantine_flags"]


def test_missing_relation_history_quarantines(tmp_path):
    receipt = evaluate(tmp_path, app_overrides={"relation_history_hash": ""})
    assert receipt["decision"] == "QUARANTINE"
    assert "missing_relation_history" in receipt["quarantine_flags"]


def test_trusted_heldout_regression_rejects(tmp_path):
    receipt = evaluate(tmp_path, app_overrides={"baseline_score": 0.80, "candidate_score": 0.795})
    assert receipt["decision"] == "REJECT"
    assert receipt["reject_flags"] == ["heldout_delta_regressed"]
    assert receipt["promotion_intent"] is None


def test_trusted_critical_failure_rejects(tmp_path):
    receipt = evaluate(tmp_path, app_overrides={"critical_failures": 1})
    assert receipt["decision"] == "REJECT"
    assert receipt["reject_flags"] == ["critical_failure_detected"]
    assert receipt["promotion_intent"] is None


def test_missing_appraisal_quarantines(tmp_path):
    pol = policy(tmp_path)
    prop = proposal()
    gate = SuccessorPromotionGate(pol)
    receipt = gate.evaluate(proposal=prop, appraisal=None, current_version_hash=prop.source_version_hash, now=2000.0)
    assert receipt["decision"] == "QUARANTINE"
    assert receipt["quarantine_flags"] == ["missing_eval_airlock_appraisal"]


def test_invalid_frozen_policy_hash_fails_constructor(tmp_path):
    try:
        SuccessorPromotionGate(policy(tmp_path, expected_policy_hash="not-a-hash"))
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_materialized_store_required_when_policy_requires_it(tmp_path):
    try:
        SuccessorPromotionGate(policy(tmp_path, appraisal_receipt_dir=""))
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_frozen_benchmark_passes():
    root = Path(__file__).resolve().parents[1] / "benchmarks" / "successor-promotion"
    result = run_frozen_benchmark(root)
    assert result["passed"] is True
    assert result["case_count"] == 26
    assert result["decision_counts"] == {"PROMOTE": 1, "QUARANTINE": 22, "REJECT": 3}
    assert all((row["promotion_intent"] is not None) == (row["decision"] == "PROMOTE") for row in result["cases"])


def test_independent_verifier_imports_no_package():
    root = Path(__file__).resolve().parents[1] / "benchmarks" / "successor-promotion"
    text = (root / "verify_independent.py").read_text(encoding="utf-8")
    assert "import olp_swarm_gate" not in text
    assert "from olp_swarm_gate" not in text


def test_nan_candidate_score_quarantines(tmp_path):
    # Strict signed receipts refuse NaN before serialization. Exercise the gate's
    # shape validator with materialization/signature requirements disabled.
    pol = policy(tmp_path, require_materialized_appraisal_receipt=False, require_signed_appraisal_receipt=False)
    prop = proposal()
    app = appraisal(pol, prop, materialize=False, candidate_score=float("nan"), appraisal_receipt_hash=h("nan-appraisal"))
    receipt = SuccessorPromotionGate(pol).evaluate(proposal=prop, appraisal=app, current_version_hash=prop.source_version_hash, now=2000.0)
    assert receipt["decision"] == "QUARANTINE"
    assert "invalid_candidate_score" in receipt["quarantine_flags"]


def test_infinite_receiver_time_quarantines(tmp_path):
    receipt = evaluate(tmp_path, now=float("inf"))
    assert receipt["decision"] == "QUARANTINE"
    assert "invalid_receiver_time" in receipt["quarantine_flags"]


def test_negative_critical_failure_count_quarantines(tmp_path):
    receipt = evaluate(tmp_path, app_overrides={"critical_failures": -1})
    assert receipt["decision"] == "QUARANTINE"
    assert "invalid_critical_failures" in receipt["quarantine_flags"]


def test_nonboolean_evaluation_complete_quarantines(tmp_path):
    receipt = evaluate(tmp_path, app_overrides={"evaluation_complete": 1})
    assert receipt["decision"] == "QUARANTINE"
    assert "invalid_evaluation_complete" in receipt["quarantine_flags"]


def test_finite_inputs_that_overflow_delta_quarantine(tmp_path):
    receipt = evaluate(tmp_path, app_overrides={"baseline_score": -1e308, "candidate_score": 1e308})
    assert receipt["decision"] == "QUARANTINE"
    assert receipt["quarantine_flags"] == ["nonfinite_heldout_delta"]


def test_malformed_proposal_id_fails_closed_without_crash(tmp_path):
    for value in [None, 123, [], {}]:
        case_root = tmp_path / ("case-" + type(value).__name__ + "-" + str(len(str(value))))
        case_root.mkdir(parents=True, exist_ok=True)
        prop = proposal(proposal_id=value)
        receipt = evaluate(case_root, prop=prop)
        assert receipt["decision"] == "QUARANTINE"
        assert "invalid_proposal_id" in receipt["quarantine_flags"]
        assert receipt["promotion_intent"] is None


def test_receipt_document_has_exact_claim_not_locator_hash(tmp_path):
    pol = policy(tmp_path)
    prop = proposal()
    app = appraisal(pol, prop, materialize=False)
    doc = build_appraisal_receipt_document(app, TEST_EVALUATOR_KEY)
    assert "appraisal_receipt_hash" not in doc["appraisal"]
    assert doc["witness"] == {"evaluator_id": app.evaluator_id, "evaluator_hash": app.evaluator_hash}


def test_unhashable_change_summary_fails_closed_without_crash(tmp_path):
    prop = proposal(change_summary=b"not-json")
    receipt = evaluate(tmp_path, prop=prop)
    assert receipt["decision"] == "QUARANTINE"
    assert "invalid_change_summary" in receipt["quarantine_flags"]
    assert receipt["proposal_hash"] is None
    assert receipt["promotion_intent"] is None


def test_unserializable_caller_metadata_is_dropped_not_crashing_gate(tmp_path):
    receipt = evaluate(tmp_path, metadata={"bad": b"bytes"})
    assert receipt["decision"] == "PROMOTE"
    assert receipt["metadata"] == {"metadata_rejected": True}
    assert receipt["gate_assertions"]["promotion_requires_receiver_pinned_evaluator_signature"] is True


def test_policy_rejects_public_key_fingerprint_mismatch(tmp_path):
    try:
        SuccessorPromotionGate(policy(tmp_path, expected_evaluator_hash=h("not-key")))
    except ValueError as exc:
        assert "fingerprint" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_copied_public_metadata_with_attacker_signature_cannot_promote(tmp_path):
    pol = policy(tmp_path)
    prop = proposal()
    raw = appraisal(pol, prop, materialize=False, candidate_score=0.99)
    forged = build_appraisal_receipt_document(raw, TEST_ATTACKER_KEY)
    digest = appraisal_receipt_digest(forged)
    bound = replace(raw, appraisal_receipt_hash=digest)
    receipt_dir = Path(pol.appraisal_receipt_dir)
    receipt_dir.mkdir(parents=True, exist_ok=True)
    (receipt_dir / f"{digest}.json").write_text(json.dumps(forged, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    receipt = SuccessorPromotionGate(pol).evaluate(proposal=prop, appraisal=bound, current_version_hash=prop.source_version_hash, now=2000.0)
    assert receipt["decision"] == "QUARANTINE"
    assert receipt["quarantine_flags"] == ["appraisal_signer_not_pinned"]
    assert receipt["promotion_intent"] is None


def test_copied_pinned_key_with_fake_signature_cannot_promote(tmp_path):
    pol = policy(tmp_path)
    prop = proposal()
    raw = appraisal(pol, prop, materialize=False, candidate_score=0.99)
    forged = build_appraisal_receipt_document(raw, TEST_EVALUATOR_KEY)
    forged["signature"]["value"] = "00" * 64
    digest = appraisal_receipt_digest(forged)
    bound = replace(raw, appraisal_receipt_hash=digest)
    receipt_dir = Path(pol.appraisal_receipt_dir)
    receipt_dir.mkdir(parents=True, exist_ok=True)
    (receipt_dir / f"{digest}.json").write_text(json.dumps(forged, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    receipt = SuccessorPromotionGate(pol).evaluate(proposal=prop, appraisal=bound, current_version_hash=prop.source_version_hash, now=2000.0)
    assert receipt["decision"] == "QUARANTINE"
    assert receipt["quarantine_flags"] == ["appraisal_signature_invalid"]


def test_unsigned_content_addressed_appraisal_cannot_promote(tmp_path):
    pol = policy(tmp_path)
    prop = proposal()
    raw = appraisal(pol, prop, materialize=False, candidate_score=0.99)
    body = unsigned_appraisal_receipt_body(raw)
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    unsigned = {**body, "payload_hash": hashlib.sha256(canonical).hexdigest()}
    digest = appraisal_receipt_digest(unsigned)
    bound = replace(raw, appraisal_receipt_hash=digest)
    receipt_dir = Path(pol.appraisal_receipt_dir)
    receipt_dir.mkdir(parents=True, exist_ok=True)
    (receipt_dir / f"{digest}.json").write_text(json.dumps(unsigned, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    receipt = SuccessorPromotionGate(pol).evaluate(proposal=prop, appraisal=bound, current_version_hash=prop.source_version_hash, now=2000.0)
    assert receipt["decision"] == "QUARANTINE"
    assert receipt["quarantine_flags"] == ["appraisal_signature_missing"]


def test_reused_signature_cannot_cover_changed_score(tmp_path):
    pol = policy(tmp_path)
    prop = proposal()
    original = appraisal(pol, prop, materialize=False, candidate_score=0.82)
    document = build_appraisal_receipt_document(original, TEST_EVALUATOR_KEY)
    document["appraisal"]["candidate_score"] = 0.99
    body = {k: document[k] for k in ("schema", "receipt_type", "witness", "appraisal")}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    document["payload_hash"] = hashlib.sha256(canonical).hexdigest()
    digest = appraisal_receipt_digest(document)
    changed = replace(original, candidate_score=0.99, appraisal_receipt_hash=digest)
    receipt_dir = Path(pol.appraisal_receipt_dir)
    receipt_dir.mkdir(parents=True, exist_ok=True)
    (receipt_dir / f"{digest}.json").write_text(json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    receipt = SuccessorPromotionGate(pol).evaluate(proposal=prop, appraisal=changed, current_version_hash=prop.source_version_hash, now=2000.0)
    assert receipt["decision"] == "QUARANTINE"
    assert receipt["quarantine_flags"] == ["appraisal_signature_invalid"]


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    functions = [(name, obj) for name, obj in globals().items() if name.startswith("test_") and callable(obj)]
    for name, fn in sorted(functions):
        def run_test(fn=fn):
            params = inspect.signature(fn).parameters
            if "tmp_path" in params:
                with tempfile.TemporaryDirectory(prefix="swarm-test-") as td:
                    fn(Path(td))
            else:
                fn()
        suite.addTest(unittest.FunctionTestCase(run_test, description=name))
    return suite
