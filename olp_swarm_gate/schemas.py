from __future__ import annotations

from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Any, Dict, Optional
import time


class ImprovementDecision(str, Enum):
    COMMIT = "COMMIT"
    QUARANTINE = "QUARANTINE"
    NO_BADGE = "NO_BADGE"


class PromotionDecision(str, Enum):
    PROMOTE = "PROMOTE"
    QUARANTINE = "QUARANTINE"
    REJECT = "REJECT"


@dataclass(frozen=True)
class MutationProposal:
    """A proposed self-change from a swarm member."""
    mutation_id: str
    proposer: str
    target_component: str
    mutation_type: str
    claim: str
    old_behavior_hash: str
    new_behavior_hash: str
    change_summary: str
    parent_version_hash: str
    proposed_version_hash: str
    timestamp: float = field(default_factory=time.time)

    def to_public_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class FitnessReport:
    """Independent evaluation evidence for the proposed mutation."""
    evaluator_id: str
    benchmark_id: str
    benchmark_version: str
    benchmark_owner: str
    evaluator_is_proposer: bool
    optimized_metric_name: str
    optimized_metric_before: float
    optimized_metric_after: float
    heldout_set_hash: Optional[str]
    heldout_metric_name: Optional[str]
    heldout_metric_before: Optional[float]
    heldout_metric_after: Optional[float]
    grader_receipt_hash: Optional[str]
    eval_receipt_hash: Optional[str]
    timestamp: float = field(default_factory=time.time)

    def to_public_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class HealthReport:
    """Health evidence for the candidate version."""
    monitor_id: str
    health_receipt_hash: Optional[str]
    badge: str
    kappa_eff: float = 0.0
    delta_hol: float = 0.0
    cycle_score: float = 0.0
    ucr: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_public_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SuccessorProposal:
    """Version A proposes one exact successor B for promotion."""
    proposal_id: str
    proposer_id: str
    source_version_id: str
    source_version_hash: str
    successor_version_id: str
    successor_version_hash: str
    change_summary: str
    created_at: float

    def to_public_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EvalAirlockAppraisal:
    """Receiver-consumable appraisal evidence produced outside the successor."""
    appraisal_receipt_hash: str
    evaluator_id: str
    evaluator_hash: str
    benchmark_id: str
    benchmark_version: str
    benchmark_owner: str
    heldout_set_hash: str
    policy_hash: str
    relation_history_hash: str
    source_version_hash: str
    successor_version_hash: str
    baseline_score: float
    candidate_score: float
    critical_failures: int
    evaluation_complete: bool
    evidence_status: str
    issued_at: float

    def to_public_dict(self) -> Dict[str, Any]:
        return asdict(self)
