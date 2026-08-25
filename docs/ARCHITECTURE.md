# Architecture

Murmur has two stateful components with a strict ownership boundary.

```text
application
    |
    | transactional MurmurStore
    v
@slopus/murmur
    | identity root
    | MLS epochs and ratchets
    | replay records and exact outboxes
    | pending-session buffers
    |
    | HTTPS: invitation digests + signed delivery + ordered SSE
    v
@slopus/murmur-relay
    | non-enumerable five-minute discovery cache
    | one queue per recipient identity
    | unacknowledged and unexpired delivery references only
    v
SQLite or Postgres
```

## Client ownership

`MurmurClient` owns one single-device Ed25519 identity derived from a 32-byte
root. The same identity authenticates discovery bundles, relay operations, and
MLS credentials. The supplied `MurmurStore` is authoritative for:

- the identity root;
- the separate invitation-revocation root and bounded digest-to-KeyPackage
  records;
- unused private KeyPackages;
- active, creating, and pending MLS checkpoints;
- sender ratchets and exact publication outboxes;
- inbox cursor, replay protection, and terminal rejections;
- asynchronous role and membership intents, pending-session state, bounded opaque event buffers, and
  the identity-wide application-update order;
- built-in contacts and session-to-service ownership.

An identity-wide contact profile revision is mirrored into every active
contact record. Updating it and queuing one MLS outbox for every active
technical contact session is one transaction, so local reads can never observe
a published revision without its durable outbound work.

Each confirmed contact also owns an offline admission inventory: fifteen
one-use public KeyPackages from the peer plus one reusable last-resort package.
The matching private bundles live only in the peer's store. Group creation
consumes cached material locally, queues refill before depletion, and can reuse
the fallback while that peer is offline.

Application history is not reconstructed from the relay. Murmur never exposes
its storage transaction to event handlers. All durable client state is compound
keys over one ordered byte key/value store with bounded lexicographic prefix
scans. Active-session events enter one identity-wide UUIDv7-ordered local
index. Contact handling, registered service callbacks, and global `onUpdates`
participate in one batch; Murmur removes it only after every relevant callback
resolves. Custom services own any application persistence separately from
`MurmurStore`.

## Relay ownership

The relay authenticates identities but does not interpret ciphertext. An
accepted multicast receives one UUIDv7 event ID and one queue reference per
recipient. UUID order is guaranteed only inside an individual inbox.

The relay stores a public signed discovery bundle for at most five minutes
under the SHA-256 digest of its exact bytes. It cannot enumerate invitations or
resolve an identity; recipients already holding the digest fetch the bytes and
independently verify the hash, signed expiry, identity signature, and
KeyPackages.

For owner-authorized uploads it additionally stores the public revocation key.
Revocation replaces a live invitation with a bounded tombstone carrying only
digest, public authority, original expiry, and admission principal. Tombstones
block public re-upload resurrection, count toward item quotas, and are pruned
at expiry; they contain no private capability.

The relay stores a delivery while at least one queue reference is
unacknowledged and unexpired. A signed monotonic acknowledgement removes one
recipient's processed prefix. The last reference removal deletes the delivery.
TTL, recipient, sender, and global quotas bound pending storage.

Realtime receiving uses one recipient-signed SSE connection. The stream carries
each exact queued delivery with its UUIDv7 ID, applies transport backpressure,
and advances its in-memory emission cursor in inbox order. The durable client
cursor remains authoritative: reconnect starts there, and acknowledgement still
occurs only after local processing commits.

The relay has no account registry, discovery directory or listing, application
history, MLS state, or application-level acknowledgement protocol.

## Session ordering

Every Commit carries the complete owner, admin, and policy state in MLS
authenticated data. Any current member may create a Commit, but each recipient
deterministically validates the change against the role state of the epoch it
extends. One relay multicast receives one shared UUIDv7 event ID in every
recipient inbox, so the first valid Commit for an epoch wins identically for
all retained members. There is no session-level committer role.

Membership publication is an operation:

```text
validate full operation manifest
          |
publish every Welcome
          |
publish Commit only after all Welcome markers
          |
adopt only from the sender's own queue echo
```

Membership and role APIs persist bounded intents before network I/O. A losing
concurrent Commit is cancelled when the earlier relay event arrives; dependent
application outboxes are re-encrypted against the winning epoch and the intent
is retried, including a replacement Welcome for a pending joiner. Application
and control outboxes are durably ordered per client. A transient head failure
blocks later records for the same session while unrelated sessions continue.

## Processing boundary

Inbox processing and application handoff follow two related invariants:

```text
page or SSE event -> authenticate/decrypt
                  -> persist protocol state + buffered update or rejection + cursor
                  -> commit -> acknowledge through cursor

ordered buffered batch -> contact + service handlers
                       -> await lifecycle hooks + onUpdates(batch)
                       -> local commit of the whole batch
```

A crash before the local commit leaves the relay item pending. A crash after
that commit causes only acknowledgement retry. Separately, a thrown
`onUpdates` callback or crash before its batch commit leaves the same stable
update IDs pending locally. Terminal malformed data is durably rejected so it
cannot block the identity queue.
