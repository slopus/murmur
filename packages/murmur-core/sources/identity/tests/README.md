# Identity tests

Tests cover request confidentiality, authentication and recipient binding,
response establishment, persistent lifecycle transitions, replay and
authenticated-ID collisions, atomic outbox rollback, symmetric friend-channel
derivation, opaque MLS-invitation-sized payloads, expiry metadata, topic
authorization secrets/signatures, crossed-request convergence, identity-free
outer envelopes, strict Ed25519 points, causal predecessors, state-specific
terminal intents, outbox ID collisions, pre-decode bounds, secret cleanup, and
atomic control persistence. Restart regressions distinguish unpublished
canceled request IDs from the last mutually-known generation.
