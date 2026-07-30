# Stack Position

- **Eval Airlock:** produces the appraisal evidence and signs the exact appraisal with its evaluator key.
- **Swarm Improvement Gate:** verifies the receiver-pinned evaluator signature plus evidence/policy bindings and decides whether this exact successor deserves propagation.
- **Receipt Gate / Verified Commit:** decides whether the exact promotion action may execute now.

v0.2.0rc3 strengthens the first handoff with receiver-pinned Ed25519 appraisal provenance. It does not absorb evaluation or execution authority into the Swarm Gate.
