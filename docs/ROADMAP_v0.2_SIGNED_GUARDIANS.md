# Roadmap: v0.2 Signed Guardians

v0.1.3 enforces distinct, mutation-bound guardian receipts inside a local hash chain.

That is enough to prevent:

```text
fake guardian receipt hashes
one guardian issuing two receipts as quorum
approval replay across unrelated mutations
```

It is not enough to prove independent real-world guardian identity.

## v0.2 target

Add signed guardian approvals.

## Required pieces

```text
guardian keypairs
guardian public-key registry
guardian approval payload
signature over approval payload
signature verification before quorum counts
append-only or externally witnessed guardian chain
```

## Approval payload

```json
{
  "guardian_id": "guardian_a",
  "guardian_public_key": "ed25519:...",
  "approves_mutation_id": "mut_001",
  "approves_proposal_hash": "sha256:...",
  "decision": "COMMIT",
  "timestamp": 0.0,
  "signature": "ed25519:..."
}
```

## Quorum rule

```text
quorum = distinct verified public keys
not distinct strings
not distinct receipt hashes
```

## Honest v0.2 claim

A protected mutation only counts guardian approval when distinct registered guardian keys sign approval for this exact mutation and proposal hash.
