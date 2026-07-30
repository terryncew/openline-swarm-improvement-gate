# OpenLine Swarm Improvement Gate

## v0.2.0rc3 — Successor Promotion, signed-appraisal bound

A self-improving system should not be allowed to certify its own successor.

This release hardens the bounded `successor_promotion` profile:

```text
version A proposes version B
        ↓
Eval Airlock-compatible appraisal artifact
        ↓
receiver resolves a signed + content-addressed appraisal
        ↓
receiver-pinned Ed25519 evaluator key + held-out set + policy
        ↓
PROMOTE / QUARANTINE / REJECT
        ↓
PROMOTE only: exact promotion intent
        ↓
Receipt Gate / Verified Commit may enforce one exact promotion
```

The public rule is simple:

> A self-improving system can propose its successor. Promotion requires a valid appraisal signature from a receiver-pinned evaluator key the successor is not assumed to control.

The existing swarm mutation gate remains intact. This release does not add a server, dashboard, model trainer, agent runtime, or autonomous self-modification loop.

## What rc3 closes

rc2 made appraisal hashes resolve to exact receiver-owned artifacts, but copied evaluator metadata could still impersonate provenance if the attacker could author a new artifact. rc3 closes that seam.

The appraisal receipt now carries an Ed25519 signature over the full witness + appraisal body. The receiver pins the evaluator public key and its SHA-256 fingerprint in policy. A copied evaluator id/hash, an attacker-signed appraisal, a fake signature under the pinned public key, or a reused signature after a score swap all quarantine. Content addressing, signature provenance, policy pins, freshness, source/successor binding, and decision-history integrity are all checked before substantive scoring.

The cryptographic claim is deliberately narrower than organizational independence: a valid signature proves possession of the pinned evaluator private key. If the successor controls that private key, can rewrite receiver policy, or can replace the receiver trust boundary, this profile cannot establish independence.

The evaluator private key used by the bundled synthetic benchmark is intentionally present in the test/probe code so the fixture is reproducible. **Do not use the bundled `FROZEN_PROFILE.json` key as a production trust anchor.** A real receiver must generate and custody its own evaluator key outside successor write authority.

rc3 also removes the pytest-only release-test seam. The bundled suite runs with stdlib `unittest`; `cryptography` is the only added runtime dependency and is used for Ed25519 verification.

## Decision semantics

```text
PROMOTE      signed, materialized receiver-owned evidence supports this exact successor
QUARANTINE   evidence/history is missing, stale, malformed, self-controlled, replayed, or mismatched
REJECT       trusted complete held-out evidence establishes a substantive failure
```

`PROMOTE` is not execution. The Swarm Improvement Gate emits an exact intent only for `PROMOTE`; Receipt Gate / Verified Commit owns any one-time version swap.

## Cross-stack responsibility

```text
OpenLine Eval Airlock
    appraises the improvement evidence

OpenLine Swarm Improvement Gate
    resolves the appraisal receipt and decides whether the successor deserves propagation

OpenLine Receipt Gate / Verified Commit
    enforces the exact one-time promotion
```

No layer approves itself.

## Frozen benchmark

The bundled benchmark contains 26 synthetic cases under one frozen profile.

```text
PROMOTE       1
QUARANTINE   22
REJECT        3
```

In addition to the rc1 cases, rc2 freezes attacks for an invented appraisal hash, score mutation under the same receipt hash, a tampered materialized receipt, an invalid pre-existing decision chain, finite scores whose subtraction overflows, and a malformed proposal identifier.

Run the source checks:

```bash
python -m unittest discover -s tests -v
python -m olp_swarm_gate.successor_benchmark
python benchmarks/successor-promotion/verify_independent.py
python scripts/hostile_successor_probe.py
python scripts/release_check.py
```

Or after installation:

```bash
olp-swarm-gate successor-benchmark
```

The frozen benchmark JSON is package data, so the installed CLI does not depend on a source-tree `benchmarks/` directory. The independent verifier imports no `olp_swarm_gate` implementation code.

## Receiver contract

The receiver pins evaluator identity, Ed25519 public key, public-key fingerprint, benchmark id/version/owner, held-out set hash, appraisal policy hash, maximum appraisal age, minimum held-out delta, minimum candidate score, and maximum critical failures.

The signed appraisal binds one exact source version, one exact successor version, relation history, scores, failure count, evidence status, and a materialized appraisal receipt artifact. The local appraisal receipt store is part of the receiver trust boundary: if the candidate can write arbitrary files into that store, the deployment has violated the boundary this mechanism assumes.

## Existing mutation gate

The original mutation gate remains available:

```text
reflect → propose mutation → evaluate → commit or quarantine → receipt
```

It still protects ordinary swarm mutations using independent evaluation, held-out checks, health review, protected-component policy, and mutation-bound guardian receipts.

## Claim boundary

The bundled fixtures validate receiver-owned successor-promotion mechanics under frozen synthetic inputs. They do not prove live recursive self-improvement, general model superiority, organizational independence of the evaluator key holder, safe autonomous deployment, or that receiver policy/key custody is secure against a successor that can rewrite it.

The empirical question remains narrower:

> Under a frozen external evaluator and held-out tests, can a candidate successor earn promotion without controlling the evidence that certifies it?
