# Relay storage

The storage seam provides atomic multicast, ordered bounded inbox reads, signed
prefix acknowledgement, expiry pruning, continuity generation, sender and
ingress-principal quota accounting, and restore declaration.

SQLite and PostgreSQL implement the same queue model:

```text
delivery row -> exact recipient references -> per-inbox sequence
sender/principal counters -> transactional quota enforcement
acknowledgement or expiry -> reference removal -> counter reclamation
```

The same transaction seam stores per-account/per-device directory state:

```text
signed rotate/replenish -> current roster generation -> active prekey pool
ticketed exact claim -> spend budget -> consume one-time or read fallback
                     -> atomically queue pre-signed spent notification
```

One-use reference history, upload nonces, and ticket-use counters are durable.
Schema version 3 adds these tables and migrates version 2 in place without
removing pending deliveries.

Initialization accepts the current exact schema or the complete version 2
predecessor for its one in-place migration. Unexpected or incomplete tables and
metadata fail closed.
