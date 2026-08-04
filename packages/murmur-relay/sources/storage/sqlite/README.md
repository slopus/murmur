# SQLite store

`node:sqlite`, WAL, foreign keys, and `BEGIN IMMEDIATE` make sequence allocation,
idempotency receipts, collapse deletion, and event insertion one transaction.
A covering `(topic_id, seq, encoded_bytes, expires_at)` index supplies bounded
ordered page metadata without visiting event rows or overflow pages. The primary
key then hydrates only the selected sequences inside the same read transaction.
The collapse index remains `(topic_id, author_signing_key, collapse_key)`. Only
explicitly expired event rows are pruned.

```text
BEGIN IMMEDIATE
  -> read/update topic head
  -> check event ID receipt
  -> delete collapsed predecessor
  -> insert event + receipt
COMMIT
```

The single-process writer lock gives the same per-topic monotonicity that
Postgres obtains with advisory locks.
