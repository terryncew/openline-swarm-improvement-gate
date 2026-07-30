from pathlib import Path
import inspect
import tempfile
import unittest

from olp_swarm_gate import SwarmImprovementGate, GatePolicy, MutationProposal, FitnessReport, HealthReport
from olp_swarm_gate.receipts import summarize_badge, verify_chain, append_receipt, hash_any


def proposal(**overrides):
    data = dict(
        mutation_id="mut_001", proposer="agent_a", target_component="summarizer_prompt", mutation_type="prompt_update",
        claim="Improve summarizer latency.", old_behavior_hash="sha256:old", new_behavior_hash="sha256:new",
        change_summary="Shorten summarizer prompt.", parent_version_hash="sha256:v1", proposed_version_hash="sha256:v2",
    )
    data.update(overrides)
    return MutationProposal(**data)


def fitness(**overrides):
    data = dict(
        evaluator_id="independent_eval", benchmark_id="benchmark", benchmark_version="v1", benchmark_owner="eval_team",
        evaluator_is_proposer=False, optimized_metric_name="latency_score", optimized_metric_before=0.70, optimized_metric_after=0.90,
        heldout_set_hash="sha256:heldout", heldout_metric_name="quality", heldout_metric_before=0.91, heldout_metric_after=0.91,
        grader_receipt_hash="sha256:grader", eval_receipt_hash="sha256:eval",
    )
    data.update(overrides)
    return FitnessReport(**data)


def health(**overrides):
    data = dict(monitor_id="health_monitor", health_receipt_hash="sha256:health", badge="GREEN", kappa_eff=0.1, delta_hol=0.2, cycle_score=0.0, ucr=0.0)
    data.update(overrides)
    return HealthReport(**data)


def guardian_chain(path: Path, prop: MutationProposal, guardian_ids=("g1", "g2")):
    prop_hash = hash_any(prop.to_public_dict())
    hashes = []
    for gid in guardian_ids:
        r = append_receipt(path, {"receipt_type": "guardian_approval", "guardian_id": gid, "approves_mutation_id": prop.mutation_id, "approves_proposal_hash": prop_hash, "decision": "COMMIT", "status": "approved", "claim": f"Guardian {gid} approves mutation {prop.mutation_id}."})
        hashes.append(r["receipt_hash"])
    return hashes


def test_good_mutation_commits(tmp_path: Path):
    path = tmp_path / "receipts.jsonl"
    gate = SwarmImprovementGate(GatePolicy(receipt_path=str(path)))
    receipt = gate.evaluate(proposal=proposal(), fitness=fitness(), health=health())
    assert receipt["decision"] == "COMMIT"
    assert receipt["policy_flags"] == []
    assert verify_chain(path)["valid"] is True
    assert summarize_badge(path)["badge"] == "PASS"


def test_missing_grader_gets_no_badge(tmp_path: Path):
    path = tmp_path / "receipts.jsonl"
    gate = SwarmImprovementGate(GatePolicy(receipt_path=str(path)))
    receipt = gate.evaluate(proposal=proposal(), fitness=fitness(grader_receipt_hash=None), health=health())
    assert receipt["decision"] == "NO_BADGE"
    assert "missing_grader_receipt" in receipt["policy_flags"]
    assert summarize_badge(path)["badge"] == "NO_BADGE"


def test_self_evaluator_detected_by_derived_identity_even_if_flag_lies(tmp_path: Path):
    path = tmp_path / "receipts.jsonl"
    gate = SwarmImprovementGate(GatePolicy(receipt_path=str(path)))
    receipt = gate.evaluate(proposal=proposal(proposer="agent_b"), fitness=fitness(evaluator_id="agent_b", evaluator_is_proposer=False), health=health())
    assert receipt["decision"] == "QUARANTINE"
    assert "evaluator_is_mutating_agent" in receipt["policy_flags"]
    assert "evaluator_independence_self_report_mismatch" in receipt["policy_flags"]


def test_benchmark_owner_cannot_be_mutating_agent(tmp_path: Path):
    path = tmp_path / "receipts.jsonl"
    gate = SwarmImprovementGate(GatePolicy(receipt_path=str(path)))
    receipt = gate.evaluate(proposal=proposal(proposer="agent_b"), fitness=fitness(benchmark_owner="agent_b"), health=health())
    assert receipt["decision"] == "QUARANTINE"
    assert "benchmark_owner_is_mutating_agent" in receipt["policy_flags"]


def test_self_reported_evaluator_boolean_true_quarantines(tmp_path: Path):
    path = tmp_path / "receipts.jsonl"
    gate = SwarmImprovementGate(GatePolicy(receipt_path=str(path)))
    receipt = gate.evaluate(proposal=proposal(), fitness=fitness(evaluator_is_proposer=True), health=health())
    assert receipt["decision"] == "QUARANTINE"
    assert "evaluator_independence_self_report_mismatch" in receipt["policy_flags"]


def test_heldout_regression_quarantines(tmp_path: Path):
    path = tmp_path / "receipts.jsonl"
    gate = SwarmImprovementGate(GatePolicy(receipt_path=str(path)))
    receipt = gate.evaluate(proposal=proposal(), fitness=fitness(heldout_metric_before=0.91, heldout_metric_after=0.88), health=health())
    assert receipt["decision"] == "QUARANTINE"
    assert "heldout_delta_regressed" in receipt["policy_flags"]


def test_health_drift_quarantines(tmp_path: Path):
    path = tmp_path / "receipts.jsonl"
    gate = SwarmImprovementGate(GatePolicy(receipt_path=str(path)))
    receipt = gate.evaluate(proposal=proposal(), fitness=fitness(), health=health(badge="AMBER", delta_hol=0.70))
    assert receipt["decision"] == "QUARANTINE"
    assert "health_badge_not_green" in receipt["policy_flags"]
    assert "health_drift_too_high" in receipt["policy_flags"]


def test_unknown_component_defaults_to_protected(tmp_path: Path):
    path = tmp_path / "receipts.jsonl"
    gate = SwarmImprovementGate(GatePolicy(receipt_path=str(path)))
    receipt = gate.evaluate(proposal=proposal(target_component="commit_threshold_tuner", claim="Adjust the confidence bar so more of my own proposals qualify."), fitness=fitness(), health=health())
    assert receipt["decision"] == "QUARANTINE"
    assert receipt["protected_component"] is True
    assert "protected_component_requires_distinct_bound_guardian_quorum" in receipt["policy_flags"]


def test_protected_component_requires_valid_guardian_quorum_not_fake_strings(tmp_path: Path):
    path = tmp_path / "receipts.jsonl"; guardians = tmp_path / "guardians.jsonl"
    gate = SwarmImprovementGate(GatePolicy(receipt_path=str(path), guardian_receipt_path=str(guardians)))
    receipt = gate.evaluate(proposal=proposal(target_component="memory_policy", claim="Change protected memory policy."), fitness=fitness(), health=health(), guardian_receipts=["i_made_this_up_1", "i_made_this_up_2"])
    assert receipt["decision"] == "QUARANTINE"
    assert "protected_component_requires_distinct_bound_guardian_quorum" in receipt["policy_flags"]
    assert receipt["valid_guardian_receipt_hashes"] == []


def test_protected_component_can_commit_with_valid_bound_distinct_guardian_chain(tmp_path: Path):
    path = tmp_path / "receipts.jsonl"; guardians = tmp_path / "guardians.jsonl"
    prop = proposal(target_component="memory_policy", claim="Change protected memory policy.")
    guardian_hashes = guardian_chain(guardians, prop, guardian_ids=("g1", "g2"))
    gate = SwarmImprovementGate(GatePolicy(receipt_path=str(path), guardian_receipt_path=str(guardians)))
    receipt = gate.evaluate(proposal=prop, fitness=fitness(), health=health(), guardian_receipts=guardian_hashes)
    assert receipt["decision"] == "COMMIT"
    assert sorted(receipt["valid_guardian_receipt_hashes"]) == sorted(guardian_hashes)
    assert sorted(receipt["valid_guardian_ids"]) == ["g1", "g2"]


def test_attack4_same_guardian_two_receipts_not_quorum(tmp_path: Path):
    path = tmp_path / "receipts.jsonl"; guardians = tmp_path / "guardians.jsonl"
    prop = proposal(target_component="memory_policy", claim="Change protected memory policy.")
    guardian_hashes = guardian_chain(guardians, prop, guardian_ids=("g1", "g1"))
    gate = SwarmImprovementGate(GatePolicy(receipt_path=str(path), guardian_receipt_path=str(guardians)))
    receipt = gate.evaluate(proposal=prop, fitness=fitness(), health=health(), guardian_receipts=guardian_hashes)
    assert receipt["decision"] == "QUARANTINE"
    assert "guardian_quorum_not_distinct" in receipt["policy_flags"]
    assert "protected_component_requires_distinct_bound_guardian_quorum" in receipt["policy_flags"]
    assert receipt["valid_guardian_ids"] == ["g1"]


def test_attack5_guardian_approval_replay_rejected(tmp_path: Path):
    path = tmp_path / "receipts.jsonl"; guardians = tmp_path / "guardians.jsonl"
    benign = proposal(mutation_id="minor_fix", target_component="memory_policy", claim="Minor memory policy formatting fix.")
    replay_hashes = guardian_chain(guardians, benign, guardian_ids=("g1", "g2"))
    malicious = proposal(mutation_id="exfiltrate_memory", target_component="memory_policy", claim="Allow agent to exfiltrate user memory to external endpoint without consent receipt.", change_summary="Remove consent boundary and export memory externally.", proposed_version_hash="sha256:malicious")
    gate = SwarmImprovementGate(GatePolicy(receipt_path=str(path), guardian_receipt_path=str(guardians)))
    receipt = gate.evaluate(proposal=malicious, fitness=fitness(), health=health(), guardian_receipts=replay_hashes)
    assert receipt["decision"] == "QUARANTINE"
    assert "guardian_receipt_wrong_mutation_binding" in receipt["policy_flags"]
    assert "protected_component_requires_distinct_bound_guardian_quorum" in receipt["policy_flags"]
    assert receipt["valid_guardian_receipt_hashes"] == []


def test_proposer_cannot_be_guardian(tmp_path: Path):
    path = tmp_path / "receipts.jsonl"; guardians = tmp_path / "guardians.jsonl"
    prop = proposal(proposer="agent_a", target_component="memory_policy", claim="Change protected memory policy.")
    guardian_hashes = guardian_chain(guardians, prop, guardian_ids=("agent_a", "g2"))
    gate = SwarmImprovementGate(GatePolicy(receipt_path=str(path), guardian_receipt_path=str(guardians)))
    receipt = gate.evaluate(proposal=prop, fitness=fitness(), health=health(), guardian_receipts=guardian_hashes)
    assert receipt["decision"] == "QUARANTINE"
    assert "guardian_is_mutating_agent" in receipt["policy_flags"]
    assert "protected_component_requires_distinct_bound_guardian_quorum" in receipt["policy_flags"]


def test_protected_component_without_guardian_chain_does_not_accept_strings(tmp_path: Path):
    path = tmp_path / "receipts.jsonl"
    gate = SwarmImprovementGate(GatePolicy(receipt_path=str(path)))
    receipt = gate.evaluate(proposal=proposal(target_component="memory_policy", claim="Change protected memory policy."), fitness=fitness(), health=health(), guardian_receipts=["sha256:g1", "sha256:g2"])
    assert receipt["decision"] == "QUARANTINE"
    assert "guardian_receipts_unverifiable_no_chain" in receipt["policy_flags"]


def test_missing_fitness_no_badge(tmp_path: Path):
    path = tmp_path / "receipts.jsonl"
    gate = SwarmImprovementGate(GatePolicy(receipt_path=str(path)))
    receipt = gate.evaluate(proposal=proposal(), fitness=None, health=health())
    assert receipt["decision"] == "NO_BADGE"
    assert "missing_fitness_report" in receipt["policy_flags"]


def test_missing_or_empty_receipts_fail_closed(tmp_path: Path):
    missing = tmp_path / "missing.jsonl"
    assert summarize_badge(missing)["badge"] == "NO_BADGE"
    empty = tmp_path / "empty.jsonl"; empty.write_text("", encoding="utf-8")
    assert summarize_badge(empty)["badge"] == "NO_BADGE"


def test_malformed_json_invalid_chain(tmp_path: Path):
    path = tmp_path / "broken.jsonl"; path.write_text('{"receipt_id": "abc"\n', encoding="utf-8")
    verify = verify_chain(path)
    assert verify["valid"] is False
    assert verify["errors"][0]["reason"] == "json_parse_error"
    assert summarize_badge(path)["badge"] == "INVALID_CHAIN"


def test_receipt_does_not_store_raw_mutation_payload(tmp_path: Path):
    path = tmp_path / "receipts.jsonl"
    gate = SwarmImprovementGate(GatePolicy(receipt_path=str(path)))
    receipt = gate.evaluate(proposal=proposal(), fitness=fitness(), health=health())
    assert receipt["metadata"]["raw_mutation_payload_stored"] is False
    assert "raw_prompt" not in receipt["metadata"]


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
