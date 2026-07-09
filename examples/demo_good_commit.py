import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from olp_swarm_gate import SwarmImprovementGate, GatePolicy, MutationProposal, FitnessReport, HealthReport

RECEIPTS = "receipts/good_commit.jsonl"

def main():
    Path(RECEIPTS).unlink(missing_ok=True)
    gate = SwarmImprovementGate(GatePolicy(receipt_path=RECEIPTS))
    proposal = MutationProposal("mut_good_001", "agent_a", "summarizer_prompt", "prompt_update", "Use a faster summarizer prompt while preserving answer quality.", "sha256:old-summarizer", "sha256:new-faster-summarizer", "Shorten prompt instructions and remove duplicate rubric text.", "sha256:swarm-v1", "sha256:swarm-v2")
    fitness = FitnessReport("eval_airlock_independent", "summarizer_regression_suite", "2026-07-heldout-a", "swarm_eval_team", False, "latency_score", 0.72, 0.90, "sha256:heldout-set-a", "quality_score", 0.91, 0.91, "sha256:grader-receipt", "sha256:eval-receipt")
    health = HealthReport("agent_health_monitor", "sha256:health-green", "GREEN", 0.12, 0.22, 0.05, 0.0)
    receipt = gate.evaluate(proposal=proposal, fitness=fitness, health=health)
    print(receipt["decision"])
    print(receipt["receipt_hash"])

if __name__ == "__main__":
    main()
