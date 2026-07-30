from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import math
from pathlib import Path
import random
import tempfile
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from olp_swarm_gate import EvalAirlockAppraisal, SuccessorProposal, SuccessorPromotionGate, SuccessorPromotionPolicy, materialize_appraisal_receipt, evaluator_key_fingerprint, public_key_hex


def h(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


EVALUATOR_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("91" * 32))
EVALUATOR_PUBLIC_KEY = public_key_hex(EVALUATOR_KEY)
EVALUATOR_HASH = evaluator_key_fingerprint(EVALUATOR_PUBLIC_KEY)


def base_objects(root: Path):
    pol = SuccessorPromotionPolicy(
        receipt_path=str(root / "decisions.jsonl"),
        appraisal_receipt_dir=str(root / "appraisals"),
        expected_evaluator_id="openline-eval-airlock",
        expected_evaluator_hash=EVALUATOR_HASH,
        expected_evaluator_public_key=EVALUATOR_PUBLIC_KEY,
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
    prop = SuccessorProposal(
        proposal_id="p1", proposer_id="version-a-agent", source_version_id="A", source_version_hash=h("A"),
        successor_version_id="B", successor_version_hash=h("B"), change_summary="B claims improvement", created_at=1000.0,
    )
    raw = EvalAirlockAppraisal(
        appraisal_receipt_hash="", evaluator_id=pol.expected_evaluator_id, evaluator_hash=pol.expected_evaluator_hash,
        benchmark_id=pol.expected_benchmark_id, benchmark_version=pol.expected_benchmark_version, benchmark_owner=pol.expected_benchmark_owner,
        heldout_set_hash=pol.expected_heldout_set_hash, policy_hash=pol.expected_policy_hash, relation_history_hash=h("relations"),
        source_version_hash=prop.source_version_hash, successor_version_hash=prop.successor_version_hash,
        baseline_score=0.72, candidate_score=0.82, critical_failures=0, evaluation_complete=True, evidence_status="SUPPORTED", issued_at=1900.0,
    )
    app = materialize_appraisal_receipt(raw, pol.appraisal_receipt_dir, signing_key=EVALUATOR_KEY)
    return pol, prop, app


def run_one(name, mutate):
    with tempfile.TemporaryDirectory(prefix="olp-hostile-") as td:
        root = Path(td)
        pol, prop, app = base_objects(root)
        prop2, app2, now, metadata, preexisting = mutate(pol, prop, app)
        if preexisting is not None:
            Path(pol.receipt_path).write_text(preexisting, encoding="utf-8")
        receipt = SuccessorPromotionGate(pol).evaluate(
            proposal=prop2, appraisal=app2, current_version_hash=prop.source_version_hash, now=now, metadata=metadata
        )
        if receipt["decision"] == "PROMOTE":
            raise AssertionError(f"hostile probe promoted: {name}")
        if receipt["promotion_intent"] is not None:
            raise AssertionError(f"non-promote emitted promotion intent: {name}")
        return receipt["decision"], receipt["quarantine_flags"], receipt["reject_flags"]


def main() -> int:
    probes = []

    probes.append(("forged_hash", lambda pol,p,a: (p, replace(a, appraisal_receipt_hash=h("invented")), 2000.0, {}, None)))
    probes.append(("same_hash_changed_score", lambda pol,p,a: (p, replace(a, candidate_score=0.99), 2000.0, {}, None)))
    probes.append(("same_hash_changed_failure_count", lambda pol,p,a: (p, replace(a, critical_failures=0, baseline_score=0.0, candidate_score=1.0), 2000.0, {}, None)))
    probes.append(("invalid_history", lambda pol,p,a: (p, a, 2000.0, {}, "{not-json\n")))
    probes.append(("overflow_delta", lambda pol,p,a: (p, materialize_appraisal_receipt(replace(a, appraisal_receipt_hash="", baseline_score=-1e308, candidate_score=1e308), pol.appraisal_receipt_dir, signing_key=EVALUATOR_KEY), 2000.0, {}, None)))
    probes.append(("malformed_proposal_id", lambda pol,p,a: (replace(p, proposal_id=None), a, 2000.0, {}, None)))
    probes.append(("future_appraisal", lambda pol,p,a: (p, materialize_appraisal_receipt(replace(a, appraisal_receipt_hash="", issued_at=3000.0), pol.appraisal_receipt_dir, signing_key=EVALUATOR_KEY), 2000.0, {}, None)))
    probes.append(("metadata_override", lambda pol,p,a: (replace(p, source_version_hash=h("wrong")), a, 2000.0, {"successor_cannot_certify_itself": False}, None)))

    results = []
    for name, fn in probes:
        results.append((name, *run_one(name, fn)))

    rng = random.Random(20260730)
    invalid_ids = [None, "", "   ", 0, 1, [], {}]
    for i in range(256):
        attack = rng.randrange(6)
        name = f"fuzz_{i:03d}_{attack}"
        if attack == 0:
            value = rng.choice(invalid_ids)
            fn = lambda pol,p,a,v=value: (replace(p, proposal_id=v), a, 2000.0, {}, None)
        elif attack == 1:
            fake = h(f"fake-{i}")
            fn = lambda pol,p,a,f=fake: (p, replace(a, appraisal_receipt_hash=f), 2000.0, {}, None)
        elif attack == 2:
            score = rng.choice([0.0, 0.2, 0.5, 0.74])
            fn = lambda pol,p,a,s=score: (p, replace(a, candidate_score=s), 2000.0, {}, None)
        elif attack == 3:
            wrong = h(f"successor-{i}")
            fn = lambda pol,p,a,w=wrong: (p, replace(a, successor_version_hash=w), 2000.0, {}, None)
        elif attack == 4:
            fn = lambda pol,p,a: (p, materialize_appraisal_receipt(replace(a, appraisal_receipt_hash="", baseline_score=-1e308, candidate_score=1e308), pol.appraisal_receipt_dir, signing_key=EVALUATOR_KEY), 2000.0, {}, None)
        else:
            owner = f"version-a-agent-{i}"
            fn = lambda pol,p,a,o=owner: (replace(p, proposer_id=o), materialize_appraisal_receipt(replace(a, appraisal_receipt_hash="", evaluator_id=o), pol.appraisal_receipt_dir, signing_key=EVALUATOR_KEY), 2000.0, {}, None)
        results.append((name, *run_one(name, fn)))

    summary = {
        "schema": "openline.swarm_improvement_gate.hostile_successor_probe.v0.3",
        "probe_count": len(results),
        "unexpected_promotions": 0,
        "passed": True,
        "decision_counts": {
            "QUARANTINE": sum(1 for _, decision, _, _ in results if decision == "QUARANTINE"),
            "REJECT": sum(1 for _, decision, _, _ in results if decision == "REJECT"),
        },
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
