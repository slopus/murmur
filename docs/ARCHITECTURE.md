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
    | HTTPS: signed opaque deliveries, reads, acknowledgements
    v
@slopus/murmur-relay
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
- unused private KeyPackages;
- active, creating, and pending MLS checkpoints;
- sender ratchets and exact publication outboxes;
- inbox cursor, replay protection, and terminal rejections;
- accepted proposals, pending-session state, and bounded opaque event buffers.

Application history is not reconstructed from the relay. Event handlers run
inside the same application transaction that hands data across the Murmur
durability boundary.

## Relay ownership

The relay authenticates identities but does not interpret ciphertext. An
accepted multicast receives one UUIDv7 event ID and one queue reference per
recipient. UUID order is guaranteed only inside an individual inbox.

The relay stores a delivery while at least one queue reference is
unacknowledged and unexpired. A signed monotonic acknowledgement removes one
recipient's processed prefix. The last reference removal deletes the delivery.
TTL, recipient, sender, and global quotas bound pending storage.

The relay has no account registry, discovery directory, application history,
MLS state, or application-level acknowledgement protocol.

## Session ordering

Independent recipient queues do not provide one total order across a group.
Murmur therefore records one epoch committer. Members may send proposals, but
only the current committer accepts proposals and creates the next Commit.
Committer identity and transfer are bound into MLS authenticated data.

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

Application and proposal outboxes are durably ordered per client. A transient
head failure blocks later records for the same session while unrelated sessions
continue.

## Processing boundary

Inbox processing follows one invariant:

```text
read -> authenticate/decrypt -> persist effect or terminal rejection + cursor
     -> commit -> acknowledge through cursor
```

A crash before the local commit leaves the relay item pending. A crash after
the local commit causes only acknowledgement retry. Terminal malformed data is
durably rejected so it cannot block the identity queue.
