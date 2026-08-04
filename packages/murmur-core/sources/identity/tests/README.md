# Identity tests

Tests cover request confidentiality, authentication and recipient binding,
response establishment, persistent lifecycle transitions, replay and
authenticated-ID collisions, atomic outbox rollback, symmetric friend-channel
derivation, opaque MLS-invitation-sized payloads, expiry metadata, topic
authorization secrets/signatures, crossed-request convergence, identity-free
outer envelopes, strict Ed25519 points, causal predecessors, state-specific
terminal intents, outbox ID collisions, pre-decode bounds, secret cleanup, and
atomic control persistence. Restart regressions distinguish unpublished
canceled request IDs from the last mutually-known generation, promote a direct
late-response edge, and prevent older late responses from regressing a newer
shared predecessor.

```text
request tests -> crossed/causal lifecycle -> response tests
      |                    |                      |
 confidentiality      restart/outbox       replay/collision
      `-------------- friend-channel authentication --------'
```

The suite exercises both cryptographic envelopes and the transactional friend
book so a passing codec test cannot hide a durability regression.
