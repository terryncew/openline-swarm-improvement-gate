# Changelog

## 0.2.0rc3

Closes the evaluator-impersonation seam found during adversarial review.

- Requires each materialized successor appraisal to carry an Ed25519 signature over the full witness + appraisal body.
- Pins the evaluator public key in receiver policy and requires `expected_evaluator_hash` to equal that key's SHA-256 fingerprint.
- Quarantines unsigned appraisals, attacker-signed appraisals, fake signatures that merely copy the pinned public key, and reused signatures after score mutation.
- Expands the frozen benchmark from 22 to 26 cases: 1 PROMOTE / 22 QUARANTINE / 3 REJECT.
- Keeps the independent verifier free of `olp_swarm_gate` imports while independently verifying Ed25519 signatures.
- Replaces the pytest-only release suite with stdlib `unittest`; adds `cryptography>=42` only for the required Ed25519 primitive.
- Narrows the public claim: cryptographic provenance proves possession of the pinned evaluator key, not organizational independence or secure key custody.
- Keeps promotion execution outside this repo; Receipt Gate / Verified Commit remains the next enforcer.

## 0.2.0rc2

Hardens the successor-promotion trust boundary found during adversarial release review.

- Requires `appraisal_receipt_hash` to resolve to an exact content-addressed appraisal artifact in a receiver-configured store.
- Binds that artifact to the full presented appraisal; reused hashes cannot launder changed scores or failure counts.
- Refuses to extend an already-invalid decision receipt chain.
- Emits a promotion intent only for `PROMOTE`; `QUARANTINE` and `REJECT` are non-actionable.
- Separates immutable gate assertions from caller metadata.
- Fails closed on malformed proposal identifiers, unhashable payload fields, unserializable metadata, and non-finite derived score deltas.
- Packages the frozen benchmark data so the installed `olp-swarm-gate successor-benchmark` command works outside the source tree.
- Expands the frozen matrix from 16 to 22 cases and adds a 264-probe hostile regression script.
- Preserves the original mutation-gate API and the cross-stack split: Eval Airlock appraises, Swarm Gate decides propagation, Receipt Gate / Verified Commit executes.

## 0.2.0rc1

Added one bounded feature: the `successor_promotion` profile.

- Adds `SuccessorPromotionGate` and `SuccessorPromotionPolicy`.
- Adds `SuccessorProposal` and `EvalAirlockAppraisal` contracts.
- Adds receiver-pinned evaluator, benchmark, held-out-set, policy, freshness, source-version, successor-version, receipt, and relation-history checks.
- Adds three dispositions: `PROMOTE`, `QUARANTINE`, and `REJECT`.
- Keeps promotion execution outside this repo and emits an exact promotion intent for Receipt Gate / Verified Commit.
- Adds a frozen 16-case benchmark and independent verifier.
- Preserves the original v0.1 mutation-gate API and tests.
- Makes no new guardian-identity guarantee.
