# Receipt Schema

## Swarm improvement decision receipt

```json
{
  "schema": "openline.swarm_improvement_gate.v0.1",
  "receipt_type": "swarm_improvement_decision",
  "receipt_id": "uuid",
  "parent_hash": null,
  "timestamp": 0.0,
  "mutation_id": "mut_good_001",
  "proposer": "agent_a",
  "target_component": "summarizer_prompt",
  "mutation_type": "prompt_update",
  "claim": "Use a faster summarizer prompt while preserving quality.",
  "proposal_hash": "sha256...",
  "fitness_hash": "sha256...",
  "health_hash": "sha256...",
  "old_behavior_hash": "sha256...",
  "new_behavior_hash": "sha256...",
  "decision": "COMMIT",
  "status": "committed",
  "policy_flags": [],
  "protected_component": false,
  "guardian_receipt_hashes": [],
  "exit_path": {},
  "next_use_note": "...",
  "receipt_hash": "sha256..."
}
```

## Badge meanings

```text
PASS          all mutation receipts committed
REVIEW        one or more mutation receipts quarantined
NO_BADGE      required proof missing or empty chain
INVALID_CHAIN malformed JSON or hash-chain failure
```

## Privacy default

The receipt stores public summaries and hashes.

It does not store raw mutation payloads.
