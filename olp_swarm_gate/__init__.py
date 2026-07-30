"""OpenLine Swarm Improvement Gate v0.2.0rc3."""

__version__ = "0.2.0rc3"

from .gate import SwarmImprovementGate, GatePolicy
from .schemas import (
    MutationProposal,
    FitnessReport,
    HealthReport,
    ImprovementDecision,
    PromotionDecision,
    SuccessorProposal,
    EvalAirlockAppraisal,
)
from .receipts import verify_chain, summarize_badge, load_receipts
from .appraisal_receipts import (
    materialize_appraisal_receipt,
    verify_materialized_appraisal_receipt,
    build_appraisal_receipt_document,
    evaluator_key_fingerprint,
    public_key_hex,
)
from .successor_promotion import SuccessorPromotionGate, SuccessorPromotionPolicy

__all__ = [
    "SwarmImprovementGate",
    "GatePolicy",
    "MutationProposal",
    "FitnessReport",
    "HealthReport",
    "ImprovementDecision",
    "PromotionDecision",
    "SuccessorProposal",
    "EvalAirlockAppraisal",
    "SuccessorPromotionGate",
    "SuccessorPromotionPolicy",
    "verify_chain",
    "summarize_badge",
    "load_receipts",
    "materialize_appraisal_receipt",
    "verify_materialized_appraisal_receipt",
    "build_appraisal_receipt_document",
    "evaluator_key_fingerprint",
    "public_key_hex",
]
