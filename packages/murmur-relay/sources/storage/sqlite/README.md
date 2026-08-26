# SQLite store

```text
read ----------------------> ordinary snapshot transaction
publish / ack / prune -----> BEGIN IMMEDIATE -> commit or rollback
```

`node:sqlite`, WAL, foreign keys, and a busy timeout support one embedded relay.
Writer transactions serialize UUIDv7 allocation, quota checks, queue-reference
mutation, bounded expiration, and targeted orphan cleanup. Fanout writes are
set-based, and expiration removes a fixed delivery batch plus chunked affected
inbox rows. Reads do not prune or take the writer lock; they filter expired rows
in their stable snapshot.

Initialization requires the exact current queue schema.
