# Spec

## Mutation proposal

Required fields:

```text
mutation_id
proposer
target_component
mutation_type
claim
old_behavior_hash
new_behavior_hash
change_summary
parent_version_hash
proposed_version_hash
```

Raw prompts, raw code, and raw private memory are not required in the receipt.

The receipt stores hashes and public summaries.

## Fitness report

Required for commit:

```text
independent evaluator
benchmark id + version
optimized metric before/after
held-out set hash
held-out metric before/after
grader receipt hash
eval receipt hash
```

## Health report

Required for commit:

```text
health receipt hash
badge
κ_eff
Δhol
cycle_score
UCR
```

Default commit policy requires `GREEN`.

## Protected components

These require higher quorum:

```text
gate
evaluator
eval
airlock
monitor
policy
receipt
verifier
memory_policy
routing_policy
```

## Decisions

Missing required proof produces `NO_BADGE`.

Risky or failed evidence produces `QUARANTINE`.

Only complete and clean evidence produces `COMMIT`.


## Guardian approvals in v0.1.3

For protected components, guardian receipts must include:

```text
guardian_id
decision = COMMIT
approves_mutation_id
approves_proposal_hash
```

The gate counts distinct `guardian_id` labels whose receipts are valid and bound to the exact proposal.

This prevents:

```text
one guardian issuing two receipts to fake quorum
replaying old approvals onto a different mutation
passing fabricated hashes that do not exist in the guardian chain
```

It does not prevent:

```text
one actor minting two different guardian_id labels in a local file it controls
```

That requires signed guardian identities in v0.2.
