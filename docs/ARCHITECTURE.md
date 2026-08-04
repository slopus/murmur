# Architecture

Murmur is one stateful library over exactly one relay.

```text
application semantics (chat, documents, files, or something unknown)
                           |
                           v
                    @slopus/murmur
 identity · friends · KeyPackages · MLS · outboxes · replay · cursors
                           |
                           v
                browser-safe HTTP transport
                           |
===================== trust boundary =====================
                           |
                           v
       typed capability topics · ordered opaque events
```

The application supplies `MurmurStore`. The relay supplies ordered storage.
Murmur owns every protocol state transition between them.

## Topics

- The identity inbox is a public-writer, protected-reader `Read Topic` named
  `friend-requests`, keyed by the public identity.
- Every outgoing request carries a fresh random protected response `Read Topic`.
- Active friends derive one stable encrypted `ReadWrite Topic` named `control`.
- Every group has a separately random stable `ReadWrite Topic` named
  `group-events`. It never derives from a rotating MLS exporter.

Request and response relay envelopes use fresh one-use Ed25519 authors. Control
and group envelopes use their shared capability author, while encrypted inner
content authenticates the Murmur or MLS sender. Every group Commit and
application message is additionally sealed in a versioned outer AEAD envelope.
Its key is domain-separated from the stable random group topic secret, and its
AAD binds the envelope domain and complete group topic. The encrypted version,
random nonce, and ciphertext leave no MLS PublicMessage header or Murmur
identity credential parseable by the relay. Exact envelope sizes and timing
remain visible, so traffic analysis may still infer likely message types.

## Synchronization

`Murmur.open()` starts an internal convergence worker. Local mutations wake it;
failures back off without discarding durable work. Each pass restores and
retries exact outboxes, catches up all discovered topics, processes retained
events in sequence, replenishes KeyPackages, prepares queued operations, reads
echoes, and repeats to a bounded quiescent state. `sync()` is an optional
explicit observation/test boundary, not required caller choreography.
KeyPackage exhaustion is collected per friend: unrelated friend and group work
still converges before a deterministic typed error is surfaced.
Queued Adds are revalidated against current friendship state and dropped when
that peer is no longer active; existing-member Removes remain independent group
operations and continue. An exact staged Add is never discarded ambiguously. If
it wins after friendship has ended and its invitation is suppressed, adoption
atomically turns the original operation into a compensating Remove at the same
queue position. After an Add wins while friendship is active, its exact
invitation outbox durably names the group, peer, and source Add until
publication is confirmed. Friend-end cleanup atomically turns an unconfirmed
or accepted-but-ambiguous invitation into exactly one Remove using that source
ID. A confirmed invitation has no such marker, so ordinary friendship end does
not alter that established group membership.

Relay cursors advance in the same application-store transaction as the effect
of an inbound event. Invalid, stale, unsupported, removed-member, and
future-without-Commit payloads advance into a fixed 32-entry per-topic
quarantine metadata ring; attacker-controlled payload bodies are not retained.
Removed groups are not polled. An explicitly fresh relay whose head is behind a
stored cursor is probed from zero and reset per topic, without blocking other
topics.

## MLS ordering

Application sends persist a cloned post-ratchet epoch, retained plaintext
intent, and exact outer relay event atomically before publication. Group
fingerprints, staged Commit identity, echo matching, and outbox idempotency all
refer to those exact retained ciphertext bytes.

Membership Commits keep active epoch `E` and staged candidate `E+1` separate.
Publication does not adopt. The first valid current-epoch Commit encountered in
relay order wins:

```text
lower relay sequence
        |
        +-- exact local candidate -> promote staged E+1
        `-- competing Commit -----> apply winner, discard candidate, replan intent
```

Only a winning Add queues its private friend-channel invitation. The recipient
first verifies the invitation's Commit event ID and fingerprint at the claimed
group sequence, decrypts that exact retained envelope using the carried topic
secret, and matches its confirmation tag to the authenticated Welcome
GroupInfo. It then atomically consumes the matching private KeyPackage bundle,
installs the Welcome epoch and stable topic capability, records the invitation
replay marker, and starts its group cursor after that exact Commit.

This consistency check binds an invitation to one retained Commit and Welcome;
it does not prove to a joiner that the inviter named the relay-order winning
fork. Membership admission therefore trusts an honest inviter who is a current
group member, rather than treating relay order as a validity oracle for a
joiner.

A removed member can be added again only with a fresh KeyPackage and a new
authenticated Welcome. Reinstallation resets that group's cursor to the
winning Add Commit while retaining previously authenticated opaque events.

## Relay storage

```text
publish signed event
        |
        +-- allocate never-reused topic sequence
        +-- optionally remove older matching author + collapse key
        +-- insert opaque event
        `-- retain idempotency receipt
```

There are no snapshots, separate mutable lists, relay blobs, or ephemeral
fanout. Missing expiration means durable. Explicit expiration and collapse
remove retained rows but never rewind the head, so cursors remain stable across
sequence holes.

SQLite uses `BEGIN IMMEDIATE`. Postgres uses a per-topic advisory transaction
lock. Both allocate the sequence, apply collapse, insert the event, and record
idempotency atomically. The current schema is version 3, fresh, and
intentionally has no legacy migration path.

## Publishing

```text
durable stateful outbox event
        |
        +-- use a fresh author for request/response Read Topics
        |   or the shared write capability for control/group topics
        +-- retain the exact signed event before network access
        `-- publish once through the one configured transport
                |
                +-- relay verifies shape/signature/write key
                +-- exact receipt retry returns original sequence
                +-- new event passes future-skew/expiration policy
                `-- store commits atomically
```

The stateful facade has no relay arrays or failover ordering. It durably retains
exact outbox bytes and retries them during convergence. A first publish has no
maximum past age, so offline outbox work does not expire implicitly. Exact
retries remain idempotent after explicit expiration because the durable receipt
is checked before lifecycle policy for already-authenticated content.

## Reading and cursors

The relay has no subscription records or acknowledgements. Murmur persists its
own per-topic cursors and discovers synchronization targets from durable friend
and group state.

```text
durable cursor C
        |
        v
read events after C
        |
        +-- retained events in sequence order
        |       |
        |       `-- MurmurStore transaction:
        |              persist protocol/application effect
        |              advance durable cursor
        |
        `-- head H + exhausted flag
```

The stateful engine commits each event's protocol effect and cursor advancement
together. Sync passes are serialized. Empty head-only progress re-reads the
cursor inside a transaction and can only increase it.

Pages carry `exhausted`. Count and encoded-byte limits can make a short page
non-exhausted, so the last event advances only to its own sequence in that case.
Only an exhausted page may advance the last event, or an empty suffix, to the
topic head.

Active topics read through the single transport. Long-poll wakes are latency
hints; register-then-recheck and timeout reads preserve correctness without
them.

## Persistence

Applications supply `MurmurStore`:

```ts
interface StoreTransaction {
    get(key: string): Promise<Uint8Array | undefined>;
    set(key: string, value: Uint8Array): Promise<void>;
    delete(key: string): Promise<void>;
    list(prefix: string): Promise<ReadonlyMap<string, Uint8Array>>;
}

interface MurmurStore extends StoreTransaction {
    transaction<Result>(
        operation: (transaction: StoreTransaction) => Promise<Result>,
    ): Promise<Result>;
}
```

The library owns key and synchronization state, while the application owns the
durable store implementation. `MemoryMurmurStore` is appropriate only for tests
and examples.
