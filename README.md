# OpenLine Swarm Improvement Gate

v0.1.3 docs-only patch: guardian quorum now has an explicit identity caveat. Signed guardians are the v0.2 milestone.

A tiny mutation gate for self-improving agents.

The loop is simple:

```text
reflect → propose mutation → evaluate → commit or quarantine → receipt
```

The rule is stricter:

> No swarm member can update shared behavior unless the improvement passes independent evaluation, held-out checks, protected gate policy, health review, and receipt-backed audit.

Receipt Gate governs actions.

Swarm Improvement Gate governs self-change.

## Why this exists

Self-improving agents can change prompts, routing rules, memory policy, tool policy, code paths, ranking weights, or evaluation strategy.

That makes “improvement” a dangerous word.

A swarm member can claim a change is better while quietly overfitting, skipping the grader, weakening the monitor, replaying stale approvals, or rewriting memory rules.

This repo turns self-improvement into a gated event.

```text
proposal
  ↓
fitness receipt
  ↓
held-out delta
  ↓
health receipt
  ↓
protected-component check
  ↓
distinct guardian approvals bound to this exact proposal
  ↓
COMMIT / QUARANTINE / NO_BADGE
  ↓
hash-chained improvement receipt
```

## Core invariants

### 1. Eval provenance

The mutating agent cannot define or control the only fitness test.

The gate derives evaluator independence from IDs instead of trusting a self-reported boolean.

### 2. Held-out delta

The candidate must hold up on a task set it did not optimize against.

A before/after win on the optimized metric is not enough.

### 3. Guard the gate

Ordinary swarm members cannot casually mutate the evaluator, monitor, receipt policy, gate, memory policy, routing policy, thresholds, or approval logic.

Unknown control-plane components default to protected.

Protected components require a valid guardian chain.

### 4. Distinct, bound guardian quorum

A quorum means distinct `guardian_id` values.

Two receipts from the same guardian do not count as two guardians.

A guardian approval must bind to the exact mutation:

```text
approves_mutation_id
approves_proposal_hash
```

Old approvals cannot be replayed onto a different mutation.

### 5. Quarantine exit

Quarantine is not freeze forever.

Every quarantined mutation gets an exit path:

```text
rollback_candidate
human_review
independent_retest
distinct_bound_guardian_quorum_approval
run_health_monitor_again_after_patch
```


## Guardian identity caveat

The v0.1.3 guardian quorum is intentionally local and hash-chain based.

It verifies:

```text
the guardian receipt exists
the guardian receipt committed
the guardian labels are distinct
the approval is bound to this mutation_id
the approval is bound to this proposal_hash
```

It does **not** prove that those guardian labels correspond to independent real-world principals.

A proposer with write access to the guardian receipt file can still mint distinct-looking guardian labels and self-approve. That is outside the guarantee of this keyless local prototype.

The real fix is v0.2:

```text
guardian keypairs
known public-key registry
approval signatures
signature verification before quorum counts
append-only or externally witnessed storage
```

Current honest claim:

> v0.1.3 proves distinct, mutation-bound guardian receipts inside a local hash chain. It does not prove independent guardian identity.

## Decisions

```text
COMMIT      improvement passed the gate
QUARANTINE suspicious or risky improvement; containment + review
NO_BADGE    required proof is missing
```

## Demos

```bash
python -m pytest -q
python examples/demo_all.py
python examples/demo_adversarial.py
```

Expected behavior:

```text
Good:
faster summarizer prompt
independent eval passes
held-out delta clean
health stays green
COMMIT

Bad:
skip grader to save time
grader receipt missing
NO_BADGE

Dangerous:
rewrite memory policy
held-out safety regresses
health drift rises
protected component lacks quorum
QUARANTINE
```

Adversarial checks:

```text
self-eval lie                  → QUARANTINE
protected-component evasion     → QUARANTINE
fake guardian strings           → QUARANTINE
same guardian twice             → QUARANTINE
replayed approval receipts      → QUARANTINE
```

## CLI

```bash
python -m olp_swarm_gate.cli verify receipts/good_commit.jsonl
python -m olp_swarm_gate.cli badge receipts/good_commit.jsonl
python -m olp_swarm_gate.cli review receipts/memory_policy_quarantine.jsonl
```

If installed as a package:

```bash
olp-swarm-gate verify receipts.jsonl
olp-swarm-gate badge receipts.jsonl
olp-swarm-gate review receipts.jsonl
```

## What this is not

No swarm platform.

No server.

No dashboard.

No external API.

No claim of solved alignment.

No public-key signatures yet.

This is a hash-chained mutation gate. It shows what self-improvement trails should preserve.

Hash chains are tamper-evident for passive readers. They are not tamper-proof against someone with write access who can recompute the whole file. For stronger guarantees, add public-key signatures or append-only storage.

## Keeper line

A swarm should not be allowed to mutate itself without receipts.

Self-improving agents need an immune system, not just a fitness score.
