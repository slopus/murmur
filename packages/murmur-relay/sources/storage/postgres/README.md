# Postgres store

```text
publish / ack / prune -> lock global singleton -> mutate pending rows
read -----------------> repeatable-read snapshot, no writes
commit publish --------> transactional pg_notify(queue identity)
```

Production wraps `pg.Pool`; tests wrap PGlite. The singleton usage lock protects
pending-storage counters and monotonic UUIDv7 allocation. The public ordering
guarantee is only within one inbox. Queue rows are additionally locked while
enforcing quota through set-based target operations. Expiration deletes one
fixed delivery batch and chunks affected-inbox cleanup. Reads only filter
expired rows, avoiding serialization failures and write amplification.
LISTEN/NOTIFY wakes readers only after publication commits.

Initialization requires the exact current queue schema.
