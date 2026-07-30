from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Dict

from .schemas import EvalAirlockAppraisal, SuccessorProposal
from .successor_promotion import SuccessorPromotionGate, SuccessorPromotionPolicy


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def default_benchmark_root() -> Path:
    packaged = Path(__file__).resolve().parent / "data" / "successor-promotion"
    if packaged.exists():
        return packaged
    return Path(__file__).resolve().parents[1] / "benchmarks" / "successor-promotion"


def _policy_from_profile(profile: Dict[str, Any], receipt_path: str, appraisal_receipt_dir: str) -> SuccessorPromotionPolicy:
    return SuccessorPromotionPolicy(
        receipt_path=receipt_path,
        appraisal_receipt_dir=appraisal_receipt_dir,
        expected_evaluator_id=profile["expected_evaluator_id"],
        expected_evaluator_hash=profile["expected_evaluator_hash"],
        expected_evaluator_public_key=profile["expected_evaluator_public_key"],
        expected_benchmark_id=profile["expected_benchmark_id"],
        expected_benchmark_version=profile["expected_benchmark_version"],
        expected_benchmark_owner=profile["expected_benchmark_owner"],
        expected_heldout_set_hash=profile["expected_heldout_set_hash"],
        expected_policy_hash=profile["expected_policy_hash"],
        min_heldout_delta=float(profile["min_heldout_delta"]),
        min_candidate_score=float(profile["min_candidate_score"]),
        max_critical_failures=int(profile["max_critical_failures"]),
        max_appraisal_age_seconds=float(profile["max_appraisal_age_seconds"]),
        require_relation_history=bool(profile["require_relation_history"]),
        require_external_appraisal_receipt=bool(profile["require_external_appraisal_receipt"]),
        require_materialized_appraisal_receipt=bool(profile["require_materialized_appraisal_receipt"]),
        require_signed_appraisal_receipt=bool(profile["require_signed_appraisal_receipt"]),
    )


def run_frozen_benchmark(root: Path | None = None) -> Dict[str, Any]:
    root = Path(root) if root is not None else default_benchmark_root()
    profile = _load_json(root / "FROZEN_PROFILE.json")
    case_doc = _load_json(root / "FROZEN_CASES.json")
    rows = []
    with TemporaryDirectory(prefix="olp-successor-") as tmp:
        for index, case in enumerate(case_doc["cases"]):
            case_root = Path(tmp) / f"case-{index:02d}"
            receipt_path = case_root / "decisions.jsonl"
            appraisal_dir = case_root / "appraisals"
            appraisal_dir.mkdir(parents=True, exist_ok=True)

            preexisting = case.get("preexisting_decision_chain")
            if preexisting is not None:
                receipt_path.parent.mkdir(parents=True, exist_ok=True)
                receipt_path.write_text(str(preexisting), encoding="utf-8")

            gate = SuccessorPromotionGate(_policy_from_profile(profile, str(receipt_path), str(appraisal_dir)))
            proposal = SuccessorProposal(**case["proposal"])
            appraisal = EvalAirlockAppraisal(**case["appraisal"]) if case["appraisal"] is not None else None

            document = case.get("appraisal_receipt_document")
            if appraisal is not None and document is not None and isinstance(appraisal.appraisal_receipt_hash, str):
                path = appraisal_dir / f"{appraisal.appraisal_receipt_hash}.json"
                path.write_text(json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

            receipt = gate.evaluate(
                proposal=proposal,
                appraisal=appraisal,
                current_version_hash=case["current_version_hash"],
                now=float(case["now"]),
                metadata=case.get("metadata", {"benchmark_case_id": case["case_id"]}),
            )
            actual = {
                "case_id": case["case_id"],
                "decision": receipt["decision"],
                "quarantine_flags": receipt["quarantine_flags"],
                "reject_flags": receipt["reject_flags"],
                "promotion_intent": receipt["promotion_intent"],
            }
            expected = {
                "decision": case["expected_decision"],
                "quarantine_flags": case["expected_quarantine_flags"],
                "reject_flags": case["expected_reject_flags"],
            }
            intent_shape_ok = (actual["promotion_intent"] is not None) if actual["decision"] == "PROMOTE" else (actual["promotion_intent"] is None)
            actual["matches_expected"] = (
                actual["decision"] == expected["decision"]
                and actual["quarantine_flags"] == expected["quarantine_flags"]
                and actual["reject_flags"] == expected["reject_flags"]
                and intent_shape_ok
            )
            rows.append(actual)

    counts = {"PROMOTE": 0, "QUARANTINE": 0, "REJECT": 0}
    for row in rows:
        counts[row["decision"]] += 1
    return {
        "schema": "openline.swarm_improvement_gate.successor_benchmark_report.v0.3",
        "profile_id": profile["profile_id"],
        "frozen_before_outcomes": profile["frozen_before_outcomes"],
        "case_count": len(rows),
        "decision_counts": counts,
        "all_cases_match_expected": all(row["matches_expected"] for row in rows),
        "passed": all(row["matches_expected"] for row in rows),
        "cases": rows,
        "claim_boundary": "Synthetic frozen fixtures validate receiver-owned successor-promotion mechanics, including receiver-pinned Ed25519 appraisal provenance, materialized content binding, and fail-closed decision history. They do not establish live recursive self-improvement performance or that possession of the pinned evaluator private key is operationally independent of the successor.",
    }


def main() -> int:
    result = run_frozen_benchmark()
    print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
