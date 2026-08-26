# Storage tests

Cross-backend conformance for atomic multicast, independent trimming, pending
idempotency, recipient/sender/global quota rollback, destructive expiration,
empty-queue acknowledgement, metadata reclamation, and UUIDv7 monotonicity.
SQLite also pins the fixed expiration batch boundary.
Another regression proves a later quota rejection cannot roll that batch back.

Terminal account-deletion vectors run against SQLite and PGlite. They cover
owned outbound fanout, device inboxes, surviving shared deliveries, continuity,
replay, missing-account no-op behavior, and exact global counters. A direct
SQLite assertion checks every raw account column is empty after the cascade;
only a SHA-256 replay tombstone remains.

The shared vectors also rotate and replenish two-device directory pools, prove
one one-use package is consumed per device, exercise reusable fallback, reject
reference and upload replay, and roll the entire claim back when publishing a
spent notice would exceed a queue quota. Registering a sibling after upload
must preserve every retained device's active pool, and a byte-identical active
replenishment can be reasserted after an ambiguous transport response. Recovery
may also replace a pool while reasserting the exact currently active fallback,
but retired fallback references remain rejected.

```text
same vectors -> SQLite
             -> PGlite/Postgres adapter
             -> equal queue outcomes
```

Page selection tests pin bounded hydration and UUID cursor behavior. Long-running
SQLite and durable-fanout chaos coverage runs separately from the unit suite.
