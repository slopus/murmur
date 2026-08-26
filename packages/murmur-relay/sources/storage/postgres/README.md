# Postgres store

```text
publish / ack / prune -> lock global singleton -> mutate pending rows
read -----------------> repeatable-read snapshot, no writes
commit publish --------> transactional pg_notify(queue identity)
```

Production wraps `pg.Pool`; tests wrap PGlite. The singleton usage lock protects
pending-storage counters and monotonic UUIDv7 allocation. The public ordering
guarantee is only within one inbox. Queue rows are additionally locked while
enforcing quota through set-based target operations. The same transaction locks
and advances relay-visible session state, derives exact devices from current
rosters, and inserts every queue reference. Expiration deletes one fixed
delivery batch and chunks affected-inbox cleanup. Reads only filter expired
rows, avoiding serialization failures and write amplification. LISTEN/NOTIFY
wakes readers only after publication commits.

Initialization requires the exact current queue schema.

Schema version 3 adds account-linked directory devices, active one-use pools,
permanent reference history, upload replay markers, and ticket-use accounting.
Row and singleton locks make ticket spending, prekey consumption, and spent
notification publication one transaction. A mismatched schema version is
rejected. Account deletion locks the global singleton and atomically cascades
raw account state while repairing surviving queue and global counters.
