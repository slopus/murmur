# Architecture

Murmur is a browser-safe, stateful encrypted-communication library connected to
one deliberately dumb relay. Application and MLS layers encrypt their content;
the relay stores only signed opaque events.

## Layers

```text
application-specific protocol
        |
        v
@slopus/murmur
stateful keys · persistence · synchronization · MLS group streams
        |
        v
browser-safe RelayTransport
exactly one configured relay
        |
================ trust boundary ================
        |
@murmur/relay
typed capability policy · ordered events · SQLite/Postgres
```

There is no CLI-owned protocol in the library architecture. Two-member and
multi-member conversations use the same higher-level MLS group primitive.
Chat semantics are intentionally outside the relay and transport.

## Trust boundary

The relay is untrusted for confidentiality, application semantics, and
availability. It can withhold, delay, replay, expire, collapse, or delete data.
End-to-end cryptography must authenticate application payloads independently.

The relay can see:

- canonical topic descriptors and their authorization public keys;
- event authors, timestamps, expiration, collapse-key equality, and sizes;
- opaque event payloads and per-topic sequence activity.

It does not receive topic secret keys and does not know whether bytes represent
a profile, invitation, MLS Commit, group application message, or another future
protocol.

## Key-scoped topics

Topics are typed descriptors rather than arbitrary strings:

- `Write Topic`: designated-key writes, public reads;
- `Read Topic`: any signed writer, designated-key reads;
- `Read and Write Topic`: designated keys in both directions.

The physical store key is a hash of `(type, name, authorization public key(s))`.
One capability key may intentionally namespace several independent named
streams. Capability keys are not relay accounts and need not be Murmur identity
keys.

Applications keep secret material in `TopicAccess`:

```ts
interface TopicAccess {
    topic: RelayTopic;
    readSecretKey?: Uint8Array;
    writeSecretKey?: Uint8Array;
}
```

For protected writes, `MurmurClient` verifies that `writeSecretKey` derives the
descriptor's `writeKey`, then signs the relay event with that capability rather
than its identity. `Read Topic` writes use the client's identity because that
topic intentionally accepts any valid signing author.

For protected reads, `HttpRelayTransport` verifies the local read secret,
obtains a one-use challenge, and signs the exact topic and read parameters.
Challenge records live in `RelayStore`, so issuance and consumption may happen
on different Postgres relay instances without sticky routing. Consumption is an
atomic delete; expiration is indexed and outstanding counts are transactional.

## Ordered event storage

Each topic contains exactly one ordered event store:

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
                +-- new event passes freshness/expiration policy
                `-- store commits atomically
```

The clean client has no relay arrays, failover ordering, or generic hidden retry
loop. A higher-level durable protocol may retain an exact signed event in its
own state and retry it. Exact retries remain idempotent after the event's
timestamp window or explicit expiration because the durable receipt is checked
before freshness for already-authenticated content.

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
