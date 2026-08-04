# Relay HTTP API

`@murmur/relay` is an ordered opaque event store. It has no accounts, identity
registry, recipient queues, snapshots, mutable lists, blob service, ephemeral
fanout, or application-message semantics.

`createRelayFetchHandler()` implements the API. `HttpRelayTransport` is its
browser-safe client.

## Conventions

- JSON is UTF-8.
- Bytes are canonical unpadded base64url.
- Sequences are decimal strings because they are `bigint`.
- Timestamps are non-negative integer Unix milliseconds.
- Event IDs encode 32 random bytes.
- Ed25519 uses strict RFC 8032 verification (`zip215: false`).
- Event signatures cover recursively key-sorted canonical JSON with
  `signature` omitted.

## Topic descriptors

A physical topic ID is SHA-256 over the canonical descriptor. The descriptor,
not an arbitrary string, is carried in every signed event and read:

```ts
type RelayTopic =
    | {
          type: "write";
          name: string;
          writeKey: string;
      }
    | {
          type: "read";
          name: string;
          readKey: string;
      }
    | {
          type: "read-write";
          name: string;
          readKey: string;
          writeKey: string;
      };
```

Keys are 32-byte Ed25519 public keys. One key may namespace many independent
topic names.

- A `write` topic is publicly readable. Its writer must sign with `writeKey`.
- A `read` topic accepts any correctly signed writer. Reading requires proof of
  `readKey`.
- A `read-write` topic enforces both designated capabilities.

Capabilities are not relay accounts and are not linked to Murmur identities.

## Events

```ts
interface SignedRelayEventJson {
    version: 1;
    id: string;
    topic: RelayTopic;
    author: { signingKey: string };
    createdAt: number;
    expiresAt?: number;
    collapseKey?: string;
    payload: string;
    signature: string;
}
```

`expiresAt` is optional. Its absence means the event is durable. An expired
event is omitted from reads and may be physically pruned.

`collapseKey` is optional opaque client-selected bytes. Publishing an event with
one atomically removes older retained events in the same topic from the same
author signing key with the same collapse key. The replacement event must
contain complete replacement content. On public-write `read` topics, one author
therefore cannot collapse another author's event.

Collapse is ordered by relay arrival, not `createdAt` or any application
version. A delayed publication of older logical state can arrive later and
supersede newer retained state. Applications using collapse must authenticate a
logical version inside the opaque payload and reject regressions when applying
events. The relay does not interpret that version.

Every accepted new event receives a monotonically increasing per-topic
sequence. Expiration and collapse create legal holes; sequences are never
reused. The topic head is the greatest sequence ever allocated.

Exact `(topic, id)` retries are idempotent indefinitely. The relay validates
shape, signature, and write authorization, then checks the durable receipt
before applying future-skew or elapsed-expiration policy. A matching retry
returns its original sequence. Different authenticated content under the same ID
returns HTTP 409 `id_collision`.

## Protected reads

Protected reads use a short-lived one-use challenge. The relay never receives a
secret key.

1. The client requests a challenge for the exact topic descriptor.
2. The relay returns random challenge ID and nonce plus expiration.
3. The client signs canonical JSON containing the challenge, topic, cursor,
   limit, and wait duration with the topic read secret.
4. The relay atomically consumes the challenge and verifies the signature.

Reusing a proof, changing any read parameter, using another topic, or presenting
an expired challenge fails.

Challenges are stored by `RelayStore` and atomically deleted on consumption.
Postgres supports cross-instance issue/consume without sticky routing. Indexed
expiration and a transactional outstanding count bound cleanup and admission.

## Endpoints

### `GET /health`

Returns `{ "ok": true }` after a successful storage health check.

### `POST /v1/events`

Body: one `SignedRelayEventJson`.

Success:

```ts
{
    seq: string;
    duplicate: boolean;
}
```

New events must not have `createdAt` more than five minutes ahead of relay time
and must not already be expired. Past `createdAt` values have no age limit:
offline durable events and clients with clocks behind the relay remain
publishable. Exact durable retries bypass only future-skew and expiration checks,
never shape, signature, topic authorization, or collision checks.

### `POST /v1/read-challenges`

Body:

```ts
{
    topic: RelayTopic;
}
```

Success:

```ts
{
    id: string;
    nonce: string;
    expiresAt: number;
}
```

Only `read` and `read-write` topics need challenges.

### `POST /v1/events/read`

Body:

```ts
{
    topic: RelayTopic;
    since: string;
    limit: number;
    waitMilliseconds: number;
    proof?: {
        challengeId: string;
        signature: string;
    };
}
```

`proof` is forbidden for public `write` topics and required otherwise.

Success:

```ts
{
    events: readonly {
        seq: string;
        event: SignedRelayEventJson;
    }[];
    head: string;
    exhausted: boolean;
}
```

`events` are retained events with sequence greater than `since`, in relay
order. `exhausted` means no further retained event exists after this page.
Clients may advance from the last returned sequence to `head` only when it is
`true`. This remains correct when a count limit or encoded-byte budget truncates
the page.

An empty exhausted page may still have `head > since`: all intervening events
expired or were collapsed, so the cursor can safely advance across those holes.
An empty non-exhausted page is invalid.

`waitMilliseconds` enables long polling up to 30 seconds. The relay first reads,
registers a waiter, rechecks to close the park/publish race, then waits for a
wake or timeout and reads again.

The final serialized response is measured against `maximumJsonBodyBytes`.
Configuration must fit one maximum-sized event; a larger multi-event response
returns HTTP 413 and can be continued with a lower `limit`.

SQLite and Postgres first fetch at most `limit + 1` retained sequence and
encoded-length metadata candidates under the same head snapshot. After applying
the exact page budget, a second indexed query in the same transaction hydrates
only the selected event JSON rows. Both persist the UTF-8 length of the same
compact event JSON at publish time, so byte-budget boundaries are
backend-independent without materializing a full page limit of large events.
The first retained event is returned even when a smaller embedding-supplied
budget would otherwise exclude it.

### `OPTIONS`

Returns the configured CORS policy. CORS defaults to `*`.

## Default limits

| Limit                           |    Default |
| ------------------------------- | ---------: |
| Event payload                   |      1 MiB |
| Collapse key                    |  256 bytes |
| JSON request                    |      2 MiB |
| Events per read                 |        256 |
| Long poll                       | 30 seconds |
| Concurrent long polls           |     10,000 |
| Read challenge lifetime         | 30 seconds |
| Outstanding challenges          |     50,000 |
| Maximum future `createdAt` skew |  5 minutes |

## Storage contract

```ts
interface RelayStore {
    readPublishReceipt(topicId: string, id: string): Promise<PublishReceipt | undefined>;
    publish(event: SignedRelayEvent, topicId: string, now: number): Promise<PublishOutcome>;
    readEvents(
        topicId: string,
        since: bigint,
        limit: number,
        now: number,
        constraints: { maximumEncodedBytes: number },
    ): Promise<EventPage>;
    pruneExpired(now: number): Promise<number>;
    health(): Promise<void>;
    close(): Promise<void>;
}
```

SQLite and Postgres/PGlite implement the same fresh schema. There are no schema
migrations or compatibility readers for the superseded relay model.
An explicit version marker rejects legacy layouts before adding clean tables.
The event table stores author signing keys for collapse identity and compact
encoded event byte lengths for page allocation.
SQLite's fresh schema covers page metadata reads with
`(topic_id, seq, encoded_bytes, expires_at)`, keeping large `event_json`
overflow pages out of the candidate scan.

`WakeSource` notifications only reduce long-poll latency. Reads and timeout
rechecks preserve correctness if notifications are lost.
