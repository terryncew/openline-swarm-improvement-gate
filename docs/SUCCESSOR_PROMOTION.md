# Successor Promotion Profile

## Research question

When version A proposes version B, what evidence must B present before B deserves to replace A?

## Threat model

Assume the candidate benefits from manipulating its own evaluation. It may copy evaluator labels, invent receipts, choose easier tests, alter scores, replay evidence, or exploit broken decision history.

The receiver therefore pins the evaluator Ed25519 public key and its fingerprint, freezes the benchmark and decision rule, owns the appraisal receipt store, and requires the presented appraisal to resolve to the exact signed artifact being consumed.

## Decision semantics

`PROMOTE` is earned only when the pinned signature, materialized receipt, exact source/successor bindings, frozen policy, freshness, and held-out rule all pass.

`QUARANTINE` covers missing, malformed, stale, self-controlled, replayed, unsigned, unpinned-signer, bad-signature, tampered, or history-invalid evidence.

`REJECT` is reserved for cryptographically trusted, complete evidence that substantively fails the frozen rule.

## Separation of powers

Eval Airlock-compatible evidence supplies and signs the appraisal. Swarm Improvement Gate verifies and owns the propagation decision. Receipt Gate / Verified Commit owns actual one-time promotion execution.

A signature proves possession of the pinned private key, not organizational independence. Key custody remains a receiver deployment responsibility.

The repository’s benchmark signing key is intentionally deterministic and public through the test/probe source. It exists only to reproduce the synthetic fixture. Never reuse the bundled frozen profile key as a production evaluator trust anchor.
