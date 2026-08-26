# Storage tests

Cross-backend conformance for atomic multicast, independent trimming, pending
idempotency, recipient/sender/global quota rollback, destructive expiration,
empty-queue acknowledgement, metadata reclamation, and UUIDv7 monotonicity.
SQLite also pins the fixed expiration batch boundary.
Another regression proves a later quota rejection cannot roll that batch back.

```text
same vectors -> SQLite
             -> PGlite/Postgres adapter
             -> equal queue outcomes
```

Page selection tests pin bounded hydration and UUID cursor behavior. Long-running
SQLite and durable-fanout chaos coverage runs separately from the unit suite.
