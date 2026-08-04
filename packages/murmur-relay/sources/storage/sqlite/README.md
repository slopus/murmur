# SQLite store

`node:sqlite`, WAL, foreign keys, and `BEGIN IMMEDIATE` make sequence allocation,
idempotency receipts, collapse deletion, and event insertion one transaction.
The primary `(topic_id, seq)` index supplies bounded ordered page candidates;
the collapse index is `(topic_id, author_signing_key, collapse_key)`. Only
explicitly expired event rows are pruned.
