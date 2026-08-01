# Architecture

Murmur is a browser-safe client library connected to a deliberately dumb,
Node-only relay. Clients encrypt application data; relays retain opaque topic
state and validate the signed event envelope around it.

## Layers

```text
┌──────────────────────────────────────────────────────────────────┐
│ application                                                      │
│ message/document semantics · durable application records         │
├──────────────────────────────────────────────────────────────────┤
│ @slopus/murmur                                                   │
│ identity · contacts · direct messages · files · client cursors   │
│ shared documents                                                 │
├──────────────────────────────────────────────────────────────────┤
│ @slopus/murmur/mls                                               │
│ MLS epochs · TreeKEM · KeyPackages · Commits · group channel     │
├══════════════════════════════════════════════════════════════════┤
│ trust boundary                                                    │
├──────────────────────────────────────────────────────────────────┤
│ @murmur/relay (Node only)                                        │
│ HTTP handler · policy · SQLite/Postgres · blob links · limits    │
└──────────────────────────────────────────────────────────────────┘
```

`@slopus/murmur` is the published library. It has no Node imports or side
effects and depends only on Noble cryptography. `murmur-mls` is built into its
`@slopus/murmur/mls` subpath. The relay is intentionally not runtime-neutral:
it contains the Node HTTP server, `node:sqlite` store, Postgres adapter, and
filesystem blob backend. `murmur-chat` is the Node CLI.

## Trust boundary

The relay is untrusted for confidentiality and application semantics.

| The relay can see                                                                    | The relay cannot learn from protocol data                         |
| ------------------------------------------------------------------------------------ | ----------------------------------------------------------------- |
| Topic IDs                                                                            | Plaintext profiles, messages, files, MLS content, or documents    |
| `author.signingKey` on every relay event                                             | What a topic represents                                           |
| Event timestamps and ciphertext sizes                                                | Group name, membership, or epoch secrets                          |
| Opaque event payloads, snapshots, and list elements                                  | File keys and nonces, which stay inside encrypted message content |
| Ciphertext blob IDs and, with the local backend, ciphertext bytes in transit/storage | Direct-message or MLS plaintext                                   |

Unauthenticated reads are intentional: a topic ID is a read capability.
Authenticated event writes do not make a topic private on their own. For this
reason direct conversations use a pairwise topic derived from X25519 secret
material, rather than a topic derived from a public identity key.

The relay is still trusted for availability. It can withhold, delay, replay, or
delete data; the crypto does not prevent denial of service.

## Topic state

```text
              publish signed event
                       |
                       v
+----------------------------------------------------+
| topic                                              |
|   head sequence                                    |
|   snapshot: optional opaque bytes + version        |
|   list: ordered opaque elements + versions         |
|   retained events: bounded mutation history        |
+----------------------------------------------------+
```

- The snapshot and current list are durable while their topic remains active.
- Event bodies expire after seven days by default. A durable receipt remains,
  so retrying the same `(topic, event id)` still returns its original sequence.
- A topic is removed after 30 days without a successful publish. Reads do not
  refresh that activity timer.
- The relay does not tie blobs to topic lifecycle. The backend owns blob
  retention.

An event is one atomic mutation. It can replace or delete the snapshot and
perform at most 256 append, replace, or delete operations on the list. Snapshot
and list element versions provide optimistic concurrency. State conflicts carry
the observed snapshot and touched-element versions, rather than silently
overwriting another write.

## Publishing

```text
client.publish()
    |
    +-- create canonical JSON relay event
    +-- sign event with Ed25519
    +-- retain exact event in local outbound state
    |
    `-- publish to configured relays
             |
             +-- relay verifies signature, time, and limits
             +-- store atomically allocates topic sequence and applies mutation
             +-- relay records durable idempotency receipt
             `-- a successful duplicate returns the original sequence
```

The client retains the exact signed event until every configured relay accepts
it. Publishing is successful when at least one relay accepts it; later
`retryOutboundSettled()` retries only relays that have not accepted the event.

At the relay, a repeated `(topic, id)` is idempotent only if the canonical
signed content matches its durable receipt. Reusing an ID for different content
is a 409 `id_collision`.

## Reading, cursors, and reset

The relay has no subscription records, recipient queues, or acknowledgements.
`MurmurClient.subscribe(topic)` only adds the topic to one local client's sync
set.

```text
local cursor C
    |
    v
GET events?since=C
    |
    +-- one retained page after C
    |       |
    |       `-- application transaction:
    |              persist application effect
    |              ReceivedEvent.advanceCursor(transaction)
    |
    `-- reset: true
            |
            `-- load snapshot + every list page, then atomically install H
```

The store keeps a cursor for every `(relay ID, topic)` pair because relay
sequences are local to a relay. `advanceCursor(transaction)` rejects skips. If
the application transaction aborts, the cursor does not advance and the event
is available again.

A `MurmurClient.sync()` call reads one page per subscribed relay/topic (100
events by the current client default). Repeat `sync()` to drain additional
pages, or use the client's `events()` iterator.

A cursor becomes unusable when it precedes the oldest retained event or is
ahead of the topic head. The relay returns `reset: true`; `sync()` then returns
`{ status: "reset", resets }` and deliberately omits all events. Calling
`loadTopic()` reads state plus the complete permanent list, invokes the
application callback, and writes the new cursor in the same
`MurmurStore.transaction()`. This prevents a reset from looking like a normal
empty catch-up.

## Storage contracts

### Client storage

Applications supply a transactional `MurmurStore`:

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

The transaction is part of the protocol contract. A direct-message record and
replay marker, an application effect and cursor, or an MLS checkpoint and its
outbox record must commit together. `MemoryMurmurStore` is provided only for
tests and examples.

### Relay storage

The relay abstracts SQLite and Postgres behind `RelayStore`. A store implements
atomic publish, consistent snapshot/list/event reads, retention pruning, health,
and close. `SqliteRelayStore` serializes writes with SQLite transactions and
WAL. `PostgresRelayStore` uses per-topic advisory locks for publishing, versioned
migrations under an advisory lock, and cluster-wide try-locks for pruning.

The Postgres implementation is exercised with PGlite in tests. It has not been
tested against a live PostgreSQL service, including `PgPoolDatabase`,
cross-instance `LISTEN`/`NOTIFY`, and advisory-lock contention.

## Blobs

The relay does not offer a general unauthenticated `PUT` or `GET` blob API.
Instead the client requests a transfer link:

```text
client ── POST /upload-link ──► BlobBackend ──► PUT link
client ── POST /download-link ─► BlobBackend ──► GET link
client ─────────────────────────────────────────► bytes
```

`LocalBlobBackend` returns a relay-relative URL. It validates a signed link,
streams uploads to a same-directory temporary file, hashes the stream, and
atomically links the finished file into a sharded content-addressed tree only
when its SHA-256 matches the requested ID. A partial or mismatched upload is
not served. Downloads stream from the installed file.

Local links are HMAC-SHA256 values over a versioned link preimage containing
the HTTP method, blob ID, and expiry. Signatures are compared in constant time.
The local backend is the only backend that handles the returned relay-local
transfer route.

`S3BlobBackend` returns an absolute AWS SigV4 presigned URL, so ciphertext
bytes do not pass through the relay. Uploads require a signed
`x-amz-checksum-sha256` header derived from the blob ID. A download-link request
first performs a signed S3 `HEAD` to confirm that the object exists. The SigV4
implementation matches the published AWS presigned-GET test vector, but has
not been tested against a live S3 bucket or MinIO.

## Rate limiting and long polling

The Fetch handler creates an in-process token bucket by default:

```text
every request        ip:<client address> bucket
valid event publish  ip:<client address> bucket + author:<signing key> bucket
```

The defaults are a capacity of 1,000 tokens, a 50-token-per-second refill, and
at most 50,000 least-recently-used buckets. Reads cost 1, upload-link requests
and local signed uploads cost 10, and publishes cost 25. A rejected request
returns HTTP 429 with `Retry-After`.

Forwarded addresses are ignored unless `MURMUR_RELAY_TRUSTED_PROXIES` explicitly
sets a trusted hop count or trusted proxy IP list. This prevents an arbitrary
`X-Forwarded-For` header from bypassing the IP limit.

The default limiter is per process. With `N` relay instances, the effective
limit is roughly `N` times higher. `RateLimiter` is an interface so a shared,
store-backed limiter can replace it at the HTTP boundary.

Events may be read with a long-poll wait of at most 30 seconds. Wake sources
only reduce latency: a timeout and re-read preserve correctness if a wake is
lost. SQLite uses in-process wakes. Postgres publishes an in-transaction
notification and uses a dedicated reconnecting `LISTEN` connection to wake
waiters on other instances.
