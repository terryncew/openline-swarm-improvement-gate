# Claim Boundary

## Supported claim

OpenLine Swarm Improvement Gate v0.1.3 shows a toy pattern for gating self-improvement in agent swarms:

```text
reflect → propose mutation → independent eval → held-out check → health check → distinct bound guardian quorum if protected → commit/quarantine/no-badge → receipt
```

It emits local hash-chained receipts for mutation decisions.

## Not claimed

This repo does not claim:

- full AI alignment;
- safe recursive self-improvement;
- universal swarm governance;
- production-grade access control;
- public-key signatures;
- impossible-to-game evals.

It is a small developer primitive.

## Honest public claim

This shows what self-improvement trails should preserve.

A swarm should not be allowed to mutate itself without receipts.


## Guardian quorum boundary

The current guardian quorum is **not** a cryptographic identity system.

It checks that guardian receipts are:

```text
present in a valid guardian receipt chain
committed
distinct by guardian_id label
bound to the exact mutation_id
bound to the exact proposal_hash
```

That is useful for local demos and receipt-shape testing.

It does not prove that two independent real-world guardians approved the mutation. A proposer with write access to the guardian chain can still create two distinct-looking guardian labels.

Do not claim:

> This proves independent guardian approval.

Do claim:

> This prototype enforces distinct, mutation-bound guardian receipt labels inside a local hash chain.

Production-grade guardian approval requires public-key signatures, a trusted public-key registry, and storage the proposer cannot rewrite unilaterally.
