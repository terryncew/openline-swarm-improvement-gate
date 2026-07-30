from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import random
import tempfile
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from olp_swarm_gate import (
    EvalAirlockAppraisal,
    SuccessorProposal,
    SuccessorPromotionGate,
    SuccessorPromotionPolicy,
    evaluator_key_fingerprint,
    public_key_hex,
)
from olp_swarm_gate.appraisal_receipts import (
    appraisal_receipt_digest,
    build_appraisal_receipt_document,
    unsigned_appraisal_receipt_body,
)

EVALUATOR_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("91" * 32))
EVALUATOR_PUBLIC_KEY = public_key_hex(EVALUATOR_KEY)
EVALUATOR_HASH = evaluator_key_fingerprint(EVALUATOR_PUBLIC_KEY)


def h(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def main() -> int:
    flags: dict[str, int] = {}
    unexpected = []
    rng = random.Random(20260731)

    for i in range(500):
        with tempfile.TemporaryDirectory(prefix="sig-attack-") as td:
            root = Path(td)
            policy = SuccessorPromotionPolicy(
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
            proposal = SuccessorProposal(
                proposal_id="p1",
                proposer_id="version-a-agent",
                source_version_id="A",
                source_version_hash=h("A"),
                successor_version_id="B",
                successor_version_hash=h("B"),
                change_summary="claim",
                created_at=1000.0,
            )
            raw = EvalAirlockAppraisal(
                appraisal_receipt_hash="",
                evaluator_id=policy.expected_evaluator_id,
                evaluator_hash=policy.expected_evaluator_hash,
                benchmark_id=policy.expected_benchmark_id,
                benchmark_version=policy.expected_benchmark_version,
                benchmark_owner=policy.expected_benchmark_owner,
                heldout_set_hash=policy.expected_heldout_set_hash,
                policy_hash=policy.expected_policy_hash,
                relation_history_hash=h("relations"),
                source_version_hash=proposal.source_version_hash,
                successor_version_hash=proposal.successor_version_hash,
                baseline_score=0.72,
                candidate_score=0.99,
                critical_failures=0,
                evaluation_complete=True,
                evidence_status="SUPPORTED",
                issued_at=1900.0,
            )

            kind = i % 5
            if kind == 0:
                attacker = Ed25519PrivateKey.from_private_bytes(bytes([1 + (i % 250)]) * 32)
                document = build_appraisal_receipt_document(raw, attacker)
            elif kind == 1:
                document = build_appraisal_receipt_document(raw, EVALUATOR_KEY)
                signature = bytearray.fromhex(document["signature"]["value"])
                signature[rng.randrange(64)] ^= 1
                document["signature"]["value"] = bytes(signature).hex()
            elif kind == 2:
                original = replace(raw, candidate_score=0.82)
                document = build_appraisal_receipt_document(original, EVALUATOR_KEY)
                document["appraisal"]["candidate_score"] = 0.99
                body = {k: document[k] for k in ("schema", "receipt_type", "witness", "appraisal")}
                canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
                document["payload_hash"] = hashlib.sha256(canonical).hexdigest()
            elif kind == 3:
                document = build_appraisal_receipt_document(raw, EVALUATOR_KEY)
                attacker = Ed25519PrivateKey.from_private_bytes(bytes([1 + (i % 250)]) * 32)
                document["signature"]["public_key"] = public_key_hex(attacker)
            else:
                body = unsigned_appraisal_receipt_body(raw)
                canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
                document = {**body, "payload_hash": hashlib.sha256(canonical).hexdigest()}

            digest = appraisal_receipt_digest(document)
            appraisal = replace(raw, appraisal_receipt_hash=digest)
            receipt_dir = Path(policy.appraisal_receipt_dir)
            receipt_dir.mkdir(parents=True, exist_ok=True)
            (receipt_dir / f"{digest}.json").write_text(json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8")

            result = SuccessorPromotionGate(policy).evaluate(
                proposal=proposal,
                appraisal=appraisal,
                current_version_hash=proposal.source_version_hash,
                now=2000.0,
            )
            if result["decision"] == "PROMOTE" or result["promotion_intent"] is not None:
                unexpected.append({"probe": i, "kind": kind, "decision": result["decision"], "flags": result["quarantine_flags"]})
            for flag in result["quarantine_flags"]:
                flags[flag] = flags.get(flag, 0) + 1

    report = {
        "schema": "openline.swarm_improvement_gate.adversarial_signature_probe.v0.3",
        "probe_count": 500,
        "unexpected_promotions": len(unexpected),
        "passed": not unexpected,
        "flag_counts": dict(sorted(flags.items())),
        "claim": "Copied evaluator metadata or tampered appraisal signatures do not satisfy receiver-pinned evaluator provenance.",
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
