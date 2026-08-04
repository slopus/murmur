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
content authenticates the Murmur or MLS sender.

## Synchronization

`Murmur.open()` starts an internal convergence worker. Local mutations wake it;
failures back off without discarding durable work. Each pass restores and
retries exact outboxes, catches up all discovered topics, processes retained
events in sequence, replenishes KeyPackages, prepares queued operations, reads
echoes, and repeats to a bounded quiescent state. `sync()` is an optional
explicit observation/test boundary, not required caller choreography.

Relay cursors advance in the same application-store transaction as the effect
of an inbound event. Invalid, stale, unsupported, removed-member, and
future-without-Commit payloads advance into a fixed 32-entry per-topic
quarantine metadata ring; attacker-controlled payload bodies are not retained.
Removed groups are not polled. An explicitly fresh relay whose head is behind a
stored cursor is probed from zero and reset per topic, without blocking other
topics.

## MLS ordering

Application sends persist a cloned post-ratchet epoch, retained plaintext
intent, and exact relay event atomically before publication.

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
group sequence and matches its confirmation tag to the authenticated Welcome
GroupInfo, then atomically consumes the matching private KeyPackage bundle,
installs the Welcome epoch and stable topic capability, records the invitation
replay marker, and starts its group cursor after that exact Commit.

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
idempotency atomically. The schema is fresh and intentionally has no legacy
migration path.

## Publishing

```text
MurmurClient.publish(access, payload)
        |
        +-- choose identity signer for Read Topic
        |   or verify/use shared write capability
        +-- sign canonical event
        `-- publish once through the one configured transport
                |
                +-- relay verifies shape/signature/write key
                +-- exact receipt retry returns original sequence
                +-- new event passes future-skew/expiration policy
                `-- store commits atomically
```

The clean client has no relay arrays, failover ordering, or generic hidden retry
loop. A higher-level durable protocol may retain an exact signed event in its
own state and retry it. A first publish has no maximum past age, so offline
outbox work does not expire implicitly. Exact retries remain idempotent after
explicit expiration because the durable receipt is checked before lifecycle
policy for already-authenticated content.

## Reading and cursors

The relay has no subscription records or acknowledgements.
`MurmurClient.subscribe(access)` only adds a local synchronization target.

```text
durable cursor C
        |
        v
read events after C
        |
        +-- retained events in sequence order
        |       |
        |       `-- application transaction:
        |              persist effect
        |              advanceCursor(transaction)
        |
        `-- head H + exhausted flag
```

`ReceivedEvent.advanceCursor(transaction)` must commit with the application
effect. It rejects skipping an earlier retained event but accepts holes that the
relay has already removed.

Sync passes are serialized and pending deliveries block the same topic from
being returned again. Empty head-only progress re-reads the cursor inside a
transaction and can only increase it.

Pages carry `exhausted`. Count and encoded-byte limits can make a short page
non-exhausted, so the last event advances only to its own sequence in that case.
Only an exhausted page may advance the last event, or an empty suffix, to the
topic head.

Subscribed topics read concurrently through the single transport. Long-poll
wakes are latency hints; register-then-recheck and timeout reads preserve
correctness without them.

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
