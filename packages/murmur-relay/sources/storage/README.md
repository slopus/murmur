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
The one clean schema carries version stamp 3.

Initialization accepts only the current exact schema. A mismatched version or
unexpected or incomplete tables and metadata fail closed; there is no migration
path.
