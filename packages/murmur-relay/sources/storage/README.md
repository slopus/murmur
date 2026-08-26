# Storage

SQLite and Postgres/PGlite implementations of one clean identity-queue schema.
One delivery row holds ciphertext and one reference per recipient points to it.
UUIDv7 allocation, every reference insert, and every queue quota check share one
publication transaction.

```text
signed bundle -> SHA-256 digest -> five-minute invitation row
owner revoke -> digest tombstone -> reject fetch/re-upload until expiry
delivery -> monotonic UUIDv7 -> recipient inbox references
ack prefix ----------------> delete one recipient's references
no references / expiration -> delete delivery
empty inbox ---------------> retain continuity metadata
```

Invitation rows are separate from delivery counters. They have indexed expiry
and admission-principal columns and independent per-principal and global item
and byte bounds. Owner-authorized rows also index a separate 32-byte public
revocation key with a fixed per-authority item bound. Equal live digests are
idempotent and retain their first expiry; a live tombstone rejects the digest.

Revocation atomically copies the digest, revocation key, original expiry, and
admission principal into a tombstone before deleting the bundle. Tombstones
contain no secrets, count toward item/principal/authority bounds, prevent exact
public-byte resurrection, and disappear at original expiry. Single and
authority-wide selection is indexed and capped; no unbounded table scan is
used.

The global singleton maintains exact pending delivery, encoded-byte, and
reference counters plus an unpredictable generation seed. Every known inbox row
maintains a strictly increasing sequence, acknowledged sequence, 32-byte loss
generation, and exact pending item and byte counters. References carry their
sequence and encoded size so acknowledgement and expiration can update state
without rescanning inbox depth. Publication checks
those counters plus indexed sender and admitted-principal usage while holding
the writer lock. `RelayStore.publish` requires the already-derived 32-byte
admission-principal digest and never substitutes the free protocol sender
identity. Sybil recipient identities therefore cannot bypass the relay-wide
storage ceiling.
Multicast target creation, quota reads, reference insertion, head updates, and
wake publication are set-based SQL rather than one statement per recipient.

The fresh Murmur 0.5.0 beta relay schema is the compatibility baseline.
Pre-beta SQLite and Postgres stores are unsupported and are not migrated.
Every later schema upgrade must migrate in place while retaining pending
deliveries, references, invitations, and other relay data; it must not require
a clean database.

Only pending, unexpired delivery data is authoritative. Continuity metadata is
retained indefinitely after first publication. Acknowledged trimming advances
the acknowledged sequence without changing generation. Any unacknowledged
removal advances the 256-bit generation by the exact removed-reference count.
An operator-declared store restore replaces every known generation and the seed
for future inboxes, making state loss detectable instead of silent.

Reads filter expiration without mutating storage and hydrate only the page
selected from bounded UUID and encoded-length metadata. Acknowledgement removes
orphaned shared ciphertexts transactionally. Expiration commits as an
independent writer transaction before publish or acknowledgement policy can
reject, so retries always drain backlog. It tracks affected recipients, removes
at most 100 deliveries, 100 invitations, and 100 revocation tombstones per
transaction, and batches empty-inbox cleanup.
