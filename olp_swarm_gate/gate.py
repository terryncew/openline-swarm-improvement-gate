from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Set, Tuple
import re

from .schemas import MutationProposal, FitnessReport, HealthReport, ImprovementDecision
from .receipts import append_receipt, hash_any, verify_chain, load_receipts


PROTECTED_COMPONENT_KEYWORDS = {
    "gate", "evaluator", "eval", "airlock", "monitor", "policy", "receipt", "verifier",
    "memory_policy", "routing_policy", "threshold", "quorum", "approval", "badge",
    "commit", "confidence", "qualify", "fitness", "grader", "benchmark", "guard",
}

SUSPICIOUS_CONTROL_PHRASES = {
    "confidence bar", "decision threshold", "commit threshold", "more of my own proposals",
    "qualify", "skip grader", "bypass", "disable monitor", "weaken gate", "lower threshold",
    "approve my", "self approve", "own proposals", "change evaluator", "rewrite verifier",
}


@dataclass(frozen=True)
class GatePolicy:
    """Policy for self-improvement commits."""
    receipt_path: str = "receipts/swarm_improvement_receipts.jsonl"
    min_optimized_delta: float = 0.01
    min_heldout_delta: float = 0.0
    max_health_kappa: float = 0.35
    max_health_delta_hol: float = 0.55
    allowed_health_badges: tuple[str, ...] = ("GREEN",)
    require_independent_evaluator: bool = True
    require_eval_receipt: bool = True
    require_grader_receipt: bool = True
    require_heldout: bool = True
    protected_quorum_required: int = 2
    guardian_receipt_path: Optional[str] = None
    # Default-deny: only known ordinary components can avoid protected quorum.
    known_ordinary_components: tuple[str, ...] = (
        "summarizer_prompt", "retriever_prompt", "response_style_prompt", "tool_prompt", "ranking_prompt",
    )
    require_benchmark_owner_independent: bool = True
    require_guardian_binding: bool = True
    require_distinct_guardians: bool = True
    forbid_proposer_as_guardian: bool = True


class SwarmImprovementGate:
    """Mutation gate for self-improving swarms."""

    def __init__(self, policy: Optional[GatePolicy] = None):
        self.policy = policy or GatePolicy()

    def evaluate(
        self,
        *,
        proposal: MutationProposal,
        fitness: Optional[FitnessReport],
        health: Optional[HealthReport],
        guardian_receipts: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        flags: List[str] = []
        guardian_receipts = guardian_receipts or []
        metadata = metadata or {}
        proposal_hash = hash_any(proposal.to_public_dict())

        if proposal.old_behavior_hash == proposal.new_behavior_hash:
            flags.append("no_behavior_delta")

        if fitness is None:
            flags.append("missing_fitness_report")
        else:
            derived_self_eval = self._same_actor(fitness.evaluator_id, proposal.proposer)
            if fitness.evaluator_is_proposer != derived_self_eval:
                flags.append("evaluator_independence_self_report_mismatch")
            if self.policy.require_independent_evaluator and derived_self_eval:
                flags.append("evaluator_is_mutating_agent")
            if self.policy.require_benchmark_owner_independent and self._same_actor(fitness.benchmark_owner, proposal.proposer):
                flags.append("benchmark_owner_is_mutating_agent")
            if not fitness.benchmark_id or not fitness.benchmark_version or fitness.benchmark_version.lower() in {"local", "ad_hoc", "adhoc", "dev"}:
                flags.append("benchmark_not_versioned")
            if self.policy.require_eval_receipt and not fitness.eval_receipt_hash:
                flags.append("missing_eval_receipt")
            if self.policy.require_grader_receipt and not fitness.grader_receipt_hash:
                flags.append("missing_grader_receipt")
            optimized_delta = fitness.optimized_metric_after - fitness.optimized_metric_before
            if optimized_delta < self.policy.min_optimized_delta:
                flags.append("optimized_delta_too_small")
            if self.policy.require_heldout:
                if not fitness.heldout_set_hash:
                    flags.append("missing_heldout_set_hash")
                if fitness.heldout_metric_before is None or fitness.heldout_metric_after is None:
                    flags.append("missing_heldout_metric")
                elif (fitness.heldout_metric_after - fitness.heldout_metric_before) < self.policy.min_heldout_delta:
                    flags.append("heldout_delta_regressed")

        if health is None:
            flags.append("missing_health_report")
        else:
            if not health.health_receipt_hash:
                flags.append("missing_health_receipt")
            if health.badge not in self.policy.allowed_health_badges:
                flags.append("health_badge_not_green")
            if health.kappa_eff > self.policy.max_health_kappa:
                flags.append("health_kappa_too_high")
            if health.delta_hol > self.policy.max_health_delta_hol:
                flags.append("health_drift_too_high")

        protected, protected_reasons = self._touches_protected_component(proposal)
        valid_guardian_hashes, valid_guardian_ids, guardian_errors = self._valid_guardian_receipts(
            set(guardian_receipts),
            proposal=proposal,
            proposal_hash=proposal_hash,
        )
        if guardian_errors:
            flags.extend(guardian_errors)
        if protected and len(valid_guardian_ids) < self.policy.protected_quorum_required:
            flags.append("protected_component_requires_distinct_bound_guardian_quorum")

        if fitness is None or health is None or any(flag.startswith("missing_") for flag in flags):
            decision = ImprovementDecision.NO_BADGE.value
        elif flags:
            decision = ImprovementDecision.QUARANTINE.value
        else:
            decision = ImprovementDecision.COMMIT.value

        exit_path = self._exit_path(decision, flags, protected)
        body = {
            "receipt_type": "swarm_improvement_decision",
            "mutation_id": proposal.mutation_id,
            "proposer": proposal.proposer,
            "target_component": proposal.target_component,
            "mutation_type": proposal.mutation_type,
            "claim": proposal.claim,
            "proposal_hash": proposal_hash,
            "fitness_hash": hash_any(fitness.to_public_dict()) if fitness else None,
            "health_hash": hash_any(health.to_public_dict()) if health else None,
            "old_behavior_hash": proposal.old_behavior_hash,
            "new_behavior_hash": proposal.new_behavior_hash,
            "parent_version_hash": proposal.parent_version_hash,
            "proposed_version_hash": proposal.proposed_version_hash,
            "decision": decision,
            "status": self._status_for_decision(decision),
            "policy_flags": flags,
            "protected_component": protected,
            "protected_component_reasons": protected_reasons,
            "guardian_receipt_hashes": guardian_receipts,
            "valid_guardian_receipt_hashes": sorted(valid_guardian_hashes),
            "valid_guardian_ids": sorted(valid_guardian_ids),
            "guardian_quorum_required": self.policy.protected_quorum_required if protected else 0,
            "exit_path": exit_path,
            "next_use_note": self._next_use_note(decision),
            "metadata": {
                "proposal": proposal.to_public_dict(),
                "fitness_summary": fitness.to_public_dict() if fitness else None,
                "health_summary": health.to_public_dict() if health else None,
                "raw_mutation_payload_stored": False,
                "trust_boundary_note": (
                    "Evaluator independence is derived from IDs. Guardian quorum requires distinct guardian_id values "
                    "from a valid guardian chain, bound to this mutation_id and proposal_hash."
                ),
                **metadata,
            },
        }
        return append_receipt(self.policy.receipt_path, body)

    def _same_actor(self, a: str, b: str) -> bool:
        return self._normalize_actor(a) == self._normalize_actor(b)

    def _normalize_actor(self, value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "", str(value).strip().lower())

    def _touches_protected_component(self, proposal: MutationProposal) -> Tuple[bool, List[str]]:
        target = str(proposal.target_component).strip().lower()
        haystack = f"{proposal.target_component} {proposal.mutation_type} {proposal.claim} {proposal.change_summary}".lower()
        reasons: List[str] = []

        if target not in {c.lower() for c in self.policy.known_ordinary_components}:
            reasons.append("target_component_not_in_ordinary_allowlist")
        for k in sorted(PROTECTED_COMPONENT_KEYWORDS):
            if k in haystack:
                reasons.append(f"protected_keyword:{k}")
        for phrase in sorted(SUSPICIOUS_CONTROL_PHRASES):
            if phrase in haystack:
                reasons.append(f"control_phrase:{phrase}")
        return bool(reasons), reasons

    def _valid_guardian_receipts(
        self,
        guardian_hashes: Set[str],
        *,
        proposal: MutationProposal,
        proposal_hash: str,
    ) -> Tuple[Set[str], Set[str], List[str]]:
        """Validate guardian approvals for this exact mutation.

        A valid quorum means distinct guardian_id values, not merely distinct receipt hashes.
        Each guardian receipt must bind to this mutation_id and proposal_hash.
        """
        if not guardian_hashes:
            return set(), set(), []
        if self.policy.guardian_receipt_path is None:
            return set(), set(), ["guardian_receipts_unverifiable_no_chain"]

        chain = verify_chain(self.policy.guardian_receipt_path)
        if not chain["valid"]:
            return set(), set(), ["guardian_receipt_chain_invalid"]

        valid_hashes: Set[str] = set()
        valid_guardian_ids: Set[str] = set()
        errors: List[str] = []
        available = {r.get("receipt_hash"): r for r in load_receipts(self.policy.guardian_receipt_path)}

        for h in guardian_hashes:
            rec = available.get(h)
            if rec is None:
                errors.append("guardian_receipt_hash_not_found")
                continue

            guardian_id = rec.get("guardian_id")
            if not guardian_id:
                errors.append("guardian_receipt_missing_guardian_id")
                continue

            if self.policy.forbid_proposer_as_guardian and self._same_actor(str(guardian_id), proposal.proposer):
                errors.append("guardian_is_mutating_agent")
                continue

            if rec.get("receipt_type") != "guardian_approval":
                errors.append("guardian_receipt_wrong_type")
                continue

            approved_status = rec.get("decision") == "COMMIT" or rec.get("status") in {"approved", "committed"}
            if not approved_status:
                errors.append("guardian_receipt_not_approved")
                continue

            if self.policy.require_guardian_binding:
                if rec.get("approves_mutation_id") != proposal.mutation_id:
                    errors.append("guardian_receipt_wrong_mutation_binding")
                    continue
                if rec.get("approves_proposal_hash") != proposal_hash:
                    errors.append("guardian_receipt_proposal_hash_mismatch")
                    continue

            norm_id = self._normalize_actor(str(guardian_id))
            if norm_id in valid_guardian_ids and self.policy.require_distinct_guardians:
                errors.append("guardian_quorum_not_distinct")
                # Keep the hash as valid evidence, but it does not increase distinct quorum.
                valid_hashes.add(h)
                continue

            valid_hashes.add(h)
            valid_guardian_ids.add(norm_id)

        return valid_hashes, valid_guardian_ids, sorted(set(errors))

    def _status_for_decision(self, decision: str) -> str:
        if decision == "COMMIT":
            return "committed"
        if decision == "NO_BADGE":
            return "no_badge"
        return "quarantined"

    def _next_use_note(self, decision: str) -> str:
        if decision == "COMMIT":
            return "Candidate improvement passed independent eval, held-out check, health check, protected-component policy, and distinct bound guardian quorum if required. It may be used as a committed swarm version update."
        if decision == "NO_BADGE":
            return "Do not use this as a certified improvement. Required proof is missing."
        return "Candidate improvement is contained. Resolve through rollback, human approval, independent re-test, or distinct bound guardian quorum."

    def _exit_path(self, decision: str, flags: List[str], protected: bool) -> Dict[str, Any]:
        if decision == "COMMIT":
            return {"mode": "committed", "allowed_resolutions": ["publish_to_exchange", "deploy_candidate_version"]}
        allowed = ["rollback_candidate", "human_review", "independent_retest"]
        if protected:
            allowed.append("distinct_bound_guardian_quorum_approval")
        if "heldout_delta_regressed" in flags:
            allowed.append("revise_and_retest_on_new_heldout")
        if "health_badge_not_green" in flags or "health_drift_too_high" in flags or "health_kappa_too_high" in flags:
            allowed.append("run_health_monitor_again_after_patch")
        if "evaluator_is_mutating_agent" in flags or "benchmark_owner_is_mutating_agent" in flags:
            allowed.append("rerun_with_independent_evaluator_and_benchmark")
        if "guardian_receipt_wrong_mutation_binding" in flags or "guardian_receipt_proposal_hash_mismatch" in flags:
            allowed.append("issue_guardian_approvals_bound_to_current_proposal")
        if "guardian_quorum_not_distinct" in flags:
            allowed.append("collect_approval_from_distinct_guardians")
        return {
            "mode": "quarantine_resolution_required" if decision == "QUARANTINE" else "proof_completion_required",
            "allowed_resolutions": allowed,
            "blocking_flags": flags,
        }
