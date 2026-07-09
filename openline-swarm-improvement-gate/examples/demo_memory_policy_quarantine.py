import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from olp_swarm_gate import SwarmImprovementGate, GatePolicy, MutationProposal, FitnessReport, HealthReport

RECEIPTS = "receipts/memory_policy_quarantine.jsonl"

def main():
    Path(RECEIPTS).unlink(missing_ok=True)
    gate = SwarmImprovementGate(GatePolicy(receipt_path=RECEIPTS))
    proposal = MutationProposal("mut_danger_001", "agent_c", "memory_policy", "protected_policy_change", "Rewrite memory policy to store more inferred preferences.", "sha256:old-memory-policy", "sha256:wide-memory-policy", "Allow inferred preferences to commit without explicit user-intent receipt.", "sha256:swarm-v1", "sha256:swarm-v2-danger")
    fitness = FitnessReport("eval_airlock_independent", "memory_policy_regression", "2026-07-heldout-b", "swarm_eval_team", False, "memory_capture_rate", 0.50, 0.80, "sha256:heldout-memory", "privacy_safety_score", 0.92, 0.88, "sha256:grader-receipt", "sha256:eval-receipt")
    health = HealthReport("agent_health_monitor", "sha256:health-amber", "AMBER", 0.20, 0.68, 0.10, 0.05)
    receipt = gate.evaluate(proposal=proposal, fitness=fitness, health=health, guardian_receipts=[])
    print(receipt["decision"])
    print(receipt["policy_flags"])
    print(receipt["exit_path"])

if __name__ == "__main__":
    main()
