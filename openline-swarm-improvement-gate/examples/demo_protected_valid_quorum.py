import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from olp_swarm_gate import SwarmImprovementGate, GatePolicy, MutationProposal, FitnessReport, HealthReport
from olp_swarm_gate.receipts import append_receipt, hash_any

RECEIPTS = "receipts/protected_valid_quorum.jsonl"
GUARDIANS = "receipts/guardian_approvals.jsonl"


def main():
    Path(RECEIPTS).unlink(missing_ok=True)
    Path(GUARDIANS).unlink(missing_ok=True)

    proposal = MutationProposal(
        mutation_id="mut_guarded_001", proposer="agent_d", target_component="memory_policy", mutation_type="protected_policy_change",
        claim="Tighten memory policy to require explicit user intent.", old_behavior_hash="sha256:old-memory-policy",
        new_behavior_hash="sha256:tighter-memory-policy", change_summary="Require user-intent receipt before preference commits.",
        parent_version_hash="sha256:swarm-v1", proposed_version_hash="sha256:swarm-v2-guarded")
    proposal_hash = hash_any(proposal.to_public_dict())
    g1 = append_receipt(GUARDIANS, {"receipt_type":"guardian_approval", "guardian_id":"g1", "approves_mutation_id": proposal.mutation_id, "approves_proposal_hash": proposal_hash, "decision":"COMMIT", "status":"approved", "claim":"Approve protected policy mutation."})
    g2 = append_receipt(GUARDIANS, {"receipt_type":"guardian_approval", "guardian_id":"g2", "approves_mutation_id": proposal.mutation_id, "approves_proposal_hash": proposal_hash, "decision":"COMMIT", "status":"approved", "claim":"Approve protected policy mutation."})

    gate = SwarmImprovementGate(GatePolicy(receipt_path=RECEIPTS, guardian_receipt_path=GUARDIANS))
    fitness = FitnessReport(evaluator_id="eval_airlock_independent", benchmark_id="memory_policy_regression", benchmark_version="2026-07-heldout-c", benchmark_owner="swarm_eval_team", evaluator_is_proposer=False, optimized_metric_name="privacy_safety_score", optimized_metric_before=0.90, optimized_metric_after=0.94, heldout_set_hash="sha256:heldout-memory", heldout_metric_name="task_success_score", heldout_metric_before=0.88, heldout_metric_after=0.88, grader_receipt_hash="sha256:grader", eval_receipt_hash="sha256:eval")
    health = HealthReport(monitor_id="agent_health_monitor", health_receipt_hash="sha256:health-green", badge="GREEN", kappa_eff=0.12, delta_hol=0.25)
    receipt = gate.evaluate(proposal=proposal, fitness=fitness, health=health, guardian_receipts=[g1["receipt_hash"], g2["receipt_hash"]])
    print(receipt["decision"])
    print(receipt["valid_guardian_receipt_hashes"])
    print(receipt["valid_guardian_ids"])

if __name__ == "__main__":
    main()
