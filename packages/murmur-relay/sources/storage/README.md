# Storage

SQLite and Postgres/PGlite implementations of one clean identity-queue schema.
One delivery row holds ciphertext and one reference per recipient points to it.
UUIDv7 allocation, every reference insert, and every queue quota check share one
publication transaction.

```text
signed bundle -> SHA-256 digest -> five-minute invitation row
delivery -> monotonic UUIDv7 -> recipient inbox references
ack prefix ----------------> delete one recipient's references
no references / expiration -> delete delivery
empty inbox ---------------> delete queue metadata
```

Invitation rows are separate from delivery counters. They have indexed expiry
and admission-principal columns and independent per-principal and global item
and byte bounds. Equal digests are idempotent and retain their first expiry.

The global singleton maintains exact pending delivery, encoded-byte, and
reference counters. Every nonempty inbox row also maintains exact pending item
and byte counters, while references carry their encoded size so acknowledge and
expiration can decrement without rescanning inbox depth. Publication checks
those counters plus indexed sender and admitted-principal usage while holding
the writer lock. `RelayStore.publish` requires the already-derived 32-byte
admission-principal digest and never substitutes the free protocol sender
identity. Sybil recipient identities therefore cannot bypass the relay-wide
storage ceiling.
Multicast target creation, quota reads, reference insertion, head updates, and
wake publication are set-based SQL rather than one statement per recipient.

Only pending, unexpired data is authoritative. Empty queue metadata is deleted,
so the relay does not retain recipient tombstones or historical cursors.
Unknown empty inboxes echo the caller's `after` cursor and reveal no global
traffic counter. Numeric sequences and loss-gap watermarks do not exist.
Expiration is destructive; later MLS processing supplies the durable terminal
outcome if a required event was missed.

Reads filter expiration without mutating storage and hydrate only the page
selected from bounded UUID and encoded-length metadata. Acknowledgement removes
orphaned shared ciphertexts transactionally. Expiration commits as an
independent writer transaction before publish or acknowledgement policy can
reject, so retries always drain backlog. It tracks affected recipients, removes
at most 100 deliveries and 100 invitations per transaction, and batches
empty-inbox cleanup.
