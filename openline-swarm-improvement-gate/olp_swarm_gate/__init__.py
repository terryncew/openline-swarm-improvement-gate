"""OpenLine Swarm Improvement Gate v0.1.3.

A tiny mutation gate for self-improving agent swarms.
"""

__version__ = "0.1.3"

from .gate import SwarmImprovementGate, GatePolicy
from .schemas import MutationProposal, FitnessReport, HealthReport, ImprovementDecision
from .receipts import verify_chain, summarize_badge, load_receipts
