# Guardian Identity Hardening

The v0.1 local guardian mechanism still does not prove that distinct guardian labels correspond to independent real-world principals.

v0.2.0rc3 completes the narrower successor-appraisal milestone: successor promotion now requires a valid Ed25519 signature from a receiver-pinned evaluator key. That does **not** automatically harden the older guardian mechanism; signed guardian identity remains a separate roadmap item.
