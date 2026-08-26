# Relay storage

The storage seam provides atomic multicast, ordered bounded inbox reads, signed
prefix acknowledgement, expiry pruning, continuity generation, sender and
ingress-principal quota accounting, and restore declaration.

SQLite and PostgreSQL implement the same queue model:

```text
delivery row -> exact recipient references -> per-inbox sequence
sender/principal counters -> transactional quota enforcement
acknowledgement or expiry -> reference removal -> counter reclamation
session control -> current members/roles/epoch -> roster-derived references
owner/session deletion -> state cascade + exact reference purge -> continuity advance
sender-account deletion -> outbound purge + owned-inbox and account-state cascade
```

The same transaction seam stores per-account/per-device directory state:

```text
signed rotate/replenish -> current roster generation -> active prekey pool
ticketed exact claim -> spend budget -> consume one-time or read fallback
                     -> atomically queue pre-signed spent notification
```

One-use reference history, upload nonces, and ticket-use counters are durable.
Active device identities are globally unique and resolve to one authoritative
sender account for outbound ownership validation.
Session deletion request IDs and hashed account-deletion tombstones remain
replay-protected for the maximum delivery retention window. Account deletion
atomically removes the roster, its dependent directory rows, every owned inbox,
all outbound deliveries, and raw account-linked nonce rows while preserving
global and surviving-inbox accounting.
Session rows hold only relay-visible routing and basic role policy: owner,
members, admins, epoch, and the three policies. They cascade through exact
session deletion and owner-account deletion.
The one clean schema carries version stamp 3.

Initialization accepts only the current exact schema. A mismatched version or
unexpected or incomplete tables and metadata fail closed; older schemas require
a fresh relay database.
