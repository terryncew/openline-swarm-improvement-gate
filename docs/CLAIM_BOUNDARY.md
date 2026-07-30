# Claim Boundary — v0.2.0rc3

This release demonstrates a receiver-owned successor-promotion mechanism on frozen synthetic fixtures.

For the bundled profile, `PROMOTE` requires the exact appraisal artifact to be materialized, content-addressed, and signed with Ed25519 by the evaluator public key pinned in receiver policy. The signature covers the full witness and appraisal body, including source/successor version hashes, scores, failure count, evidence status, policy pins, relation history, and timestamp. Copied evaluator metadata is not sufficient.

The gate also checks the pinned key fingerprint, benchmark/policy bindings, freshness, held-out thresholds, and destination decision-chain integrity. Only `PROMOTE` emits an exact promotion intent; execution remains owned by Receipt Gate / Verified Commit.

The cryptographic boundary is key possession, not sociology. A valid signature establishes that the holder of the receiver-pinned private key signed the appraisal. It does not prove that the key holder is organizationally independent of the successor. If the successor controls the evaluator private key, receiver policy, or receiver evidence store, the deployment has violated the independence assumption.

The benchmark signing key is a deterministic public test fixture and is intentionally recoverable from the repository tests/probes. The bundled frozen profile therefore must never be reused as a production trust policy; production receivers must provision a different evaluator key under receiver-controlled custody.

This release does not establish live recursive self-improvement, general predictive validity, model alignment, safe autonomous deployment, or universal evaluator independence.
