# SQLite store

`node:sqlite`, WAL, foreign keys, and `BEGIN IMMEDIATE` make sequence allocation,
idempotency receipts, collapse deletion, and event insertion one transaction.
Only explicitly expired event rows are pruned.
