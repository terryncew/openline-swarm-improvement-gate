from __future__ import annotations

from dataclasses import dataclass
import math
import re
from typing import Any, Dict, Optional

from .appraisal_receipts import evaluator_key_fingerprint, verify_materialized_appraisal_receipt
from .receipts import InvalidReceiptChainError, append_receipt, canonical_json, hash_any, verify_chain
from .schemas import EvalAirlockAppraisal, PromotionDecision, SuccessorProposal


_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _norm_actor(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return re.sub(r"[^a-z0-9]+", "", value.strip().lower())


def _is_hash(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    raw = value.strip().lower()
    if raw.startswith("sha256:"):
        raw = raw.split(":", 1)[1]
    return bool(_HEX64.fullmatch(raw))


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _safe_hash(value: Any) -> Optional[str]:
    try:
        return hash_any(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _safe_metadata(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {"metadata_rejected": True}
    try:
        canonical_json(value)
    except (TypeError, ValueError, OverflowError):
        return {"metadata_rejected": True}
    return dict(value)


@dataclass(frozen=True)
class SuccessorPromotionPolicy:
    """Frozen receiver policy for one successor-promotion profile.

    The evidence-store path is a receiver deployment binding, not part of the
    portable policy hash. The semantic requirement that the receipt be
    materialized and verified *is* frozen.
    """

    receipt_path: str = "receipts/successor_promotion_receipts.jsonl"
    appraisal_receipt_dir: str = "receipts/eval_airlock_appraisals"
    expected_evaluator_id: str = "openline-eval-airlock"
    expected_evaluator_hash: str = ""
    expected_evaluator_public_key: str = ""
    expected_benchmark_id: str = "successor-promotion"
    expected_benchmark_version: str = "v1"
    expected_benchmark_owner: str = "receiver"
    expected_heldout_set_hash: str = ""
    expected_policy_hash: str = ""
    min_heldout_delta: float = 0.0
    min_candidate_score: float = 0.0
    max_critical_failures: int = 0
    max_appraisal_age_seconds: float = 86_400.0
    require_relation_history: bool = True
    require_external_appraisal_receipt: bool = True
    require_materialized_appraisal_receipt: bool = True
    require_signed_appraisal_receipt: bool = True

    def frozen_public_dict(self) -> Dict[str, Any]:
        return {
            "expected_evaluator_id": self.expected_evaluator_id,
            "expected_evaluator_hash": self.expected_evaluator_hash,
            "expected_evaluator_public_key": self.expected_evaluator_public_key,
            "expected_benchmark_id": self.expected_benchmark_id,
            "expected_benchmark_version": self.expected_benchmark_version,
            "expected_benchmark_owner": self.expected_benchmark_owner,
            "expected_heldout_set_hash": self.expected_heldout_set_hash,
            "expected_policy_hash": self.expected_policy_hash,
            "min_heldout_delta": self.min_heldout_delta,
            "min_candidate_score": self.min_candidate_score,
            "max_critical_failures": self.max_critical_failures,
            "max_appraisal_age_seconds": self.max_appraisal_age_seconds,
            "require_relation_history": self.require_relation_history,
            "require_external_appraisal_receipt": self.require_external_appraisal_receipt,
            "require_materialized_appraisal_receipt": self.require_materialized_appraisal_receipt,
            "require_signed_appraisal_receipt": self.require_signed_appraisal_receipt,
        }

    @property
    def freeze_hash(self) -> str:
        return hash_any(self.frozen_public_dict())


class SuccessorPromotionGate:
    """Receiver-owned gate for promotion from one exact parent to one successor."""

    def __init__(self, policy: SuccessorPromotionPolicy):
        self.policy = policy
        self._validate_policy()

    def _validate_policy(self) -> None:
        required_hashes = {
            "expected_evaluator_hash": self.policy.expected_evaluator_hash,
            "expected_heldout_set_hash": self.policy.expected_heldout_set_hash,
            "expected_policy_hash": self.policy.expected_policy_hash,
        }
        for name, value in required_hashes.items():
            if not _is_hash(value):
                raise ValueError(f"{name} must be a SHA-256 digest")
        finite_policy_values = {
            "min_heldout_delta": self.policy.min_heldout_delta,
            "min_candidate_score": self.policy.min_candidate_score,
            "max_appraisal_age_seconds": self.policy.max_appraisal_age_seconds,
        }
        for name, value in finite_policy_values.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
                raise ValueError(f"{name} must be a finite number")
        if self.policy.max_appraisal_age_seconds <= 0:
            raise ValueError("max_appraisal_age_seconds must be positive")
        if isinstance(self.policy.max_critical_failures, bool) or not isinstance(self.policy.max_critical_failures, int) or self.policy.max_critical_failures < 0:
            raise ValueError("max_critical_failures must be a non-negative integer")
        if self.policy.require_materialized_appraisal_receipt and not _nonempty_string(self.policy.appraisal_receipt_dir):
            raise ValueError("appraisal_receipt_dir must be configured when materialized receipts are required")
        if self.policy.require_signed_appraisal_receipt:
            if not isinstance(self.policy.expected_evaluator_public_key, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", self.policy.expected_evaluator_public_key.strip()):
                raise ValueError("expected_evaluator_public_key must be a raw 32-byte Ed25519 public key in hex")
            try:
                fingerprint = evaluator_key_fingerprint(self.policy.expected_evaluator_public_key.strip().lower())
            except (TypeError, ValueError):
                raise ValueError("expected_evaluator_public_key must be a raw 32-byte Ed25519 public key in hex") from None
            if fingerprint != self.policy.expected_evaluator_hash.strip().lower():
                raise ValueError("expected_evaluator_hash must fingerprint expected_evaluator_public_key")

    def evaluate(
        self,
        *,
        proposal: SuccessorProposal,
        appraisal: Optional[EvalAirlockAppraisal],
        current_version_hash: str,
        now: float,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        quarantine_flags: list[str] = []
        reject_flags: list[str] = []
        caller_metadata = _safe_metadata(metadata or {})

        destination_chain = verify_chain(self.policy.receipt_path)
        destination_startable = destination_chain["missing"] or destination_chain["empty"]
        if not destination_chain["valid"] and not destination_startable:
            quarantine_flags.append("invalid_destination_receipt_chain")

        if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(float(now)):
            quarantine_flags.append("invalid_receiver_time")

        self._validate_proposal_shape(proposal, quarantine_flags)

        if current_version_hash != proposal.source_version_hash:
            quarantine_flags.append("source_version_not_current")
        if proposal.source_version_hash == proposal.successor_version_hash:
            quarantine_flags.append("successor_has_no_version_delta")

        if appraisal is None:
            quarantine_flags.append("missing_eval_airlock_appraisal")
        else:
            self._check_appraisal_binding(proposal, appraisal, quarantine_flags)
            self._check_materialized_appraisal(appraisal, quarantine_flags)
            self._check_frozen_evaluator(proposal, appraisal, quarantine_flags)
            self._check_freshness(appraisal, now, quarantine_flags)

            trusted_for_substantive_judgment = not quarantine_flags
            if trusted_for_substantive_judgment:
                if appraisal.evaluation_complete is not True:
                    quarantine_flags.append("evaluation_incomplete")
                if appraisal.evidence_status != "SUPPORTED":
                    quarantine_flags.append("appraisal_not_supported")

            trusted_and_complete = not quarantine_flags
            if trusted_and_complete:
                heldout_delta = appraisal.candidate_score - appraisal.baseline_score
                if not math.isfinite(heldout_delta):
                    quarantine_flags.append("nonfinite_heldout_delta")
                else:
                    if appraisal.critical_failures > self.policy.max_critical_failures:
                        reject_flags.append("critical_failure_detected")
                    if heldout_delta < self.policy.min_heldout_delta:
                        reject_flags.append("heldout_delta_regressed")
                    if appraisal.candidate_score < self.policy.min_candidate_score:
                        reject_flags.append("candidate_score_below_floor")

        decision = self._decision(quarantine_flags, reject_flags)
        promotion_intent = self._promotion_intent(proposal, appraisal) if decision == PromotionDecision.PROMOTE.value else None

        body = {
            "schema": "openline.swarm_improvement_gate.successor_promotion.v0.3",
            "receipt_type": "successor_promotion_decision",
            "proposal_id": proposal.proposal_id,
            "proposer_id": proposal.proposer_id,
            "source_version_id": proposal.source_version_id,
            "source_version_hash": proposal.source_version_hash,
            "successor_version_id": proposal.successor_version_id,
            "successor_version_hash": proposal.successor_version_hash,
            "proposal_hash": _safe_hash(proposal.to_public_dict()),
            "appraisal_hash": _safe_hash(appraisal.to_public_dict()) if appraisal else None,
            "appraisal_receipt_hash": appraisal.appraisal_receipt_hash if appraisal else None,
            "frozen_policy_hash": self.policy.freeze_hash,
            "decision": decision,
            "status": self._status(decision),
            "quarantine_flags": sorted(set(quarantine_flags)),
            "reject_flags": sorted(set(reject_flags)),
            "promotion_intent": promotion_intent,
            "next_use_note": self._next_use_note(decision),
            "gate_assertions": {
                "raw_successor_payload_stored": False,
                "promotion_requires_receiver_pinned_evaluator_signature": self.policy.require_signed_appraisal_receipt,
                "appraisal_content_materialized": self.policy.require_materialized_appraisal_receipt,
                "promotion_execution_owned_elsewhere": True,
            },
            "metadata": caller_metadata,
        }

        if "invalid_destination_receipt_chain" in body["quarantine_flags"]:
            return self._unpersisted(body, "invalid_destination_receipt_chain")

        try:
            return append_receipt(self.policy.receipt_path, body)
        except (InvalidReceiptChainError, OSError, TypeError, ValueError):
            body["decision"] = PromotionDecision.QUARANTINE.value
            body["status"] = self._status(body["decision"])
            body["promotion_intent"] = None
            body["reject_flags"] = []
            body["quarantine_flags"] = sorted(set(body["quarantine_flags"] + ["receipt_persistence_failed", "invalid_destination_receipt_chain"]))
            body["next_use_note"] = self._next_use_note(body["decision"])
            return self._unpersisted(body, "receipt_persistence_failed")

    def _decision(self, quarantine_flags: list[str], reject_flags: list[str]) -> str:
        if quarantine_flags:
            return PromotionDecision.QUARANTINE.value
        if reject_flags:
            return PromotionDecision.REJECT.value
        return PromotionDecision.PROMOTE.value

    def _unpersisted(self, body: Dict[str, Any], reason: str) -> Dict[str, Any]:
        out = dict(body)
        out.update({
            "receipt_id": None,
            "timestamp": None,
            "parent_hash": None,
            "receipt_hash": None,
            "receipt_persisted": False,
            "persistence_error": reason,
        })
        return out

    def _promotion_intent(self, proposal: SuccessorProposal, appraisal: Optional[EvalAirlockAppraisal]) -> Dict[str, Any]:
        return {
            "action": "promote_successor_version",
            "source_version_hash": proposal.source_version_hash,
            "successor_version_hash": proposal.successor_version_hash,
            "proposal_id": proposal.proposal_id,
            "appraisal_receipt_hash": appraisal.appraisal_receipt_hash if appraisal else None,
            "frozen_policy_hash": self.policy.freeze_hash,
            "enforcement": "NOT_EXECUTED_BY_SWARM_IMPROVEMENT_GATE",
            "next_enforcer": "openline-receipt-gate/verified-commit",
        }

    def _validate_proposal_shape(self, proposal: SuccessorProposal, flags: list[str]) -> None:
        for name, value in (
            ("proposal_id", proposal.proposal_id),
            ("proposer_id", proposal.proposer_id),
            ("source_version_id", proposal.source_version_id),
            ("successor_version_id", proposal.successor_version_id),
        ):
            if not _nonempty_string(value):
                flags.append(f"invalid_{name}")
        if not isinstance(proposal.change_summary, str):
            flags.append("invalid_change_summary")
        if not _is_hash(proposal.source_version_hash):
            flags.append("invalid_source_version_hash")
        if not _is_hash(proposal.successor_version_hash):
            flags.append("invalid_successor_version_hash")
        if isinstance(proposal.created_at, bool) or not isinstance(proposal.created_at, (int, float)) or not math.isfinite(float(proposal.created_at)):
            flags.append("invalid_proposal_timestamp")

    def _check_appraisal_binding(self, proposal: SuccessorProposal, appraisal: EvalAirlockAppraisal, flags: list[str]) -> None:
        for name, value in (("baseline_score", appraisal.baseline_score), ("candidate_score", appraisal.candidate_score), ("issued_at", appraisal.issued_at)):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
                flags.append(f"invalid_{name}")
        if isinstance(appraisal.critical_failures, bool) or not isinstance(appraisal.critical_failures, int) or appraisal.critical_failures < 0:
            flags.append("invalid_critical_failures")
        if not isinstance(appraisal.evaluation_complete, bool):
            flags.append("invalid_evaluation_complete")
        if not isinstance(appraisal.evidence_status, str):
            flags.append("invalid_evidence_status")
        if self.policy.require_external_appraisal_receipt and not _is_hash(appraisal.appraisal_receipt_hash):
            flags.append("missing_or_invalid_appraisal_receipt")
        if appraisal.source_version_hash != proposal.source_version_hash:
            flags.append("appraisal_wrong_source_version")
        if appraisal.successor_version_hash != proposal.successor_version_hash:
            flags.append("appraisal_wrong_successor_version")
        if self.policy.require_relation_history and not _is_hash(appraisal.relation_history_hash):
            flags.append("missing_relation_history")

    def _check_materialized_appraisal(self, appraisal: EvalAirlockAppraisal, flags: list[str]) -> None:
        if not self.policy.require_materialized_appraisal_receipt:
            return
        if not _is_hash(appraisal.appraisal_receipt_hash):
            return
        flags.extend(verify_materialized_appraisal_receipt(
            appraisal,
            self.policy.appraisal_receipt_dir,
            expected_public_key=self.policy.expected_evaluator_public_key,
            require_signature=self.policy.require_signed_appraisal_receipt,
        ))

    def _check_frozen_evaluator(self, proposal: SuccessorProposal, appraisal: EvalAirlockAppraisal, flags: list[str]) -> None:
        if _norm_actor(appraisal.evaluator_id) == _norm_actor(proposal.proposer_id) and _norm_actor(appraisal.evaluator_id):
            flags.append("successor_proposer_is_evaluator")
        if _norm_actor(appraisal.benchmark_owner) == _norm_actor(proposal.proposer_id) and _norm_actor(appraisal.benchmark_owner):
            flags.append("successor_proposer_owns_benchmark")
        if appraisal.evaluator_id != self.policy.expected_evaluator_id:
            flags.append("evaluator_id_not_frozen")
        if appraisal.evaluator_hash != self.policy.expected_evaluator_hash:
            flags.append("evaluator_hash_not_frozen")
        if appraisal.benchmark_id != self.policy.expected_benchmark_id:
            flags.append("benchmark_id_not_frozen")
        if appraisal.benchmark_version != self.policy.expected_benchmark_version:
            flags.append("benchmark_version_not_frozen")
        if appraisal.benchmark_owner != self.policy.expected_benchmark_owner:
            flags.append("benchmark_owner_not_frozen")
        if appraisal.heldout_set_hash != self.policy.expected_heldout_set_hash:
            flags.append("heldout_set_not_frozen")
        if appraisal.policy_hash != self.policy.expected_policy_hash:
            flags.append("appraisal_policy_not_frozen")

    def _check_freshness(self, appraisal: EvalAirlockAppraisal, now: float, flags: list[str]) -> None:
        if "invalid_receiver_time" in flags or "invalid_issued_at" in flags:
            return
        age = now - appraisal.issued_at
        if age < 0:
            flags.append("appraisal_from_future")
        elif age > self.policy.max_appraisal_age_seconds:
            flags.append("appraisal_stale")

    def _status(self, decision: str) -> str:
        if decision == PromotionDecision.PROMOTE.value:
            return "eligible_for_exact_promotion"
        if decision == PromotionDecision.REJECT.value:
            return "rejected"
        return "quarantined"

    def _next_use_note(self, decision: str) -> str:
        if decision == PromotionDecision.PROMOTE.value:
            return "Receiver-pinned held-out evidence supports this exact successor. Promotion still requires a separate exact one-time execution authorization."
        if decision == PromotionDecision.REJECT.value:
            return "Trusted held-out evidence establishes that this successor does not satisfy the frozen promotion rule. Do not promote it."
        return "Promotion evidence or receiver history is untrusted, missing, stale, self-controlled, or mismatched. Hold the successor and repair the evidence boundary before reevaluation."
