# Relay HTTP API

The relay exposes six endpoints. Every request body is authenticated by an
Ed25519 signature over a canonical payload, so the relay needs no sessions,
tokens, cookies, or CORS credentials.

Implemented by `createRelayFetchHandler` in `@murmur/relay`. The client side is
`HttpRelayTransport` in `@slopus/murmur`.

## Conventions

- Request and response bodies are JSON, except blob bodies, which are raw
  `application/octet-stream`.
- `Uint8Array` fields are base64url. Identity IDs are the 43-character base64url
  public signing key.
- Timestamps are milliseconds since the Unix epoch.
- Signed requests are valid for **±5 minutes** of relay clock time.
- CORS defaults to `*`, which is safe because the protocol is credential-free.

## Endpoints

### `POST /v1/subscriptions`

Subscribe an identity to a topic. Body is a signed `TopicSubscription`:

```typescript
{
    version: 1,
    topic: string,
    subscriber: { signingKey, encryptionKey },
    createdAt: number,
    signature: Uint8Array,
}
```

`204` on success. A first-time subscription backfills every retained event on
the topic that was not addressed to explicit recipients, so a new subscriber
replays history rather than starting empty. Re-subscribing is idempotent.

### `POST /v1/events`

Publish an opaque event. Body is a signed `RelayEvent`:

```typescript
{
    version: 1,
    id: string,
    topic: string,
    sender: { signingKey, encryptionKey },
    recipients: readonly string[],   // empty means "all topic subscribers"
    createdAt: number,
    payload: Uint8Array,             // opaque ciphertext
    signature: Uint8Array,
}
```

`204` on success. Publication is atomic with fan-out: the relay writes the event
and one delivery row per recipient in a single transaction.

Re-publishing the same `id` with identical content is a no-op. The same `id`
with different content is rejected — the relay stores a fingerprint of the
signed envelope and refuses to overwrite it.

### `POST /v1/queue/pull`

Read the caller's queue. Body is a signed `QueueReadRequest` with
`action: "read"`. Optional `?wait=<milliseconds>` long-polls, capped at 30 000.

Returns up to 16 deliveries:

```typescript
[{ deliveryId: string, event: RelayEvent }];
```

Deliveries are **not** removed by reading; they persist until acknowledged.

`requestId` is single-use: the relay records it and rejects reuse with `409`.
This prevents a captured request from being replayed to drain a queue.

With `wait`, the relay returns as soon as an event arrives, or an empty array at
timeout. A relay under long-poll pressure returns `503`.

### `POST /v1/queue/acknowledge`

Delete one queued delivery. Body is a signed `QueueAcknowledgeRequest` with
`action: "acknowledge"` and a `deliveryId`. `204` on success; idempotent.

Only call this after your application state is durably committed. See
[ARCHITECTURE.md](ARCHITECTURE.md#receiving).

### `PUT /v1/blobs/:id`

Upload ciphertext. `:id` must be the 43-character base64url SHA-256 of the body.
Body is raw bytes, up to 64 MiB. `204` on success.

The relay recomputes the hash and rejects a mismatch with `400`. Re-uploading
identical bytes is a no-op; a different body under an existing ID is rejected.
Storage is therefore self-verifying and deduplicating.

### `GET /v1/blobs/:id`

Download ciphertext as `application/octet-stream`. `404` if unknown.

There is no authentication on blob reads: possession of the 32-byte content hash
is the capability. The bytes are useless without the descriptor from the
message that referenced them.

## Status codes

| Code  | Meaning                                                      |
| ----- | ------------------------------------------------------------ |
| `204` | Success, no body                                             |
| `400` | Malformed body, bad blob hash, or invalid long-poll duration |
| `401` | Invalid or expired signature                                 |
| `404` | Unknown route or blob                                        |
| `408` | Client disconnected during a long poll                       |
| `409` | Replayed `requestId`                                         |
| `413` | Body, payload, envelope, or recipient count over limit       |
| `429` | Rate limited                                                 |
| `500` | Internal relay error                                         |
| `503` | Too many concurrent long polls                               |

## Limits

| Limit                           | Default            |
| ------------------------------- | ------------------ |
| Event payload                   | 1 MiB              |
| Event envelope                  | 2 MiB              |
| JSON request body               | 4 MiB              |
| Blob                            | 64 MiB             |
| Recipients per event            | 1 024              |
| Deliveries per pull             | 16                 |
| Delivery response               | 32 MiB             |
| Long poll                       | 30 s               |
| Concurrent long polls           | 10 000 per process |
| Signed request validity         | ±5 min             |
| Topic inactivity before pruning | 30 days            |

Configurable through `RelayOptions`, subject to protocol maxima.

## Implementing a transport

A relay is only one implementation of `RelayTransport`. Anything satisfying this
interface works — LAN, WebRTC, Bluetooth, a test double:

```typescript
interface RelayTransport {
    readonly id: string;
    publish(event: RelayEvent): Promise<void>;
    subscribe(subscription: TopicSubscription): Promise<void>;
    pull(
        request: QueueReadRequest,
        waitMilliseconds?: number,
        signal?: AbortSignal,
    ): Promise<readonly RelayDelivery[]>;
    acknowledge(request: QueueAcknowledgeRequest): Promise<void>;
    putBlob(blob: RelayBlob): Promise<void>;
    getBlob(id: string): Promise<RelayBlob | undefined>;
}
```

## Implementing a store

To host a relay on a different database, implement `RelayStore` from
`@murmur/relay` — 8 methods:

```typescript
interface RelayStore {
    addSubscription(subscription: TopicSubscription, observedAt: number): Promise<number>;
    publish(event: RelayEvent, observedAt: number): Promise<RelayPublishResult>;
    consumeQueueRequest(
        recipientId: string,
        requestId: string,
        expiresAt: number,
        observedAt: number,
    ): Promise<boolean>;
    pull(recipientId: string, maximumDeliveries: number): Promise<readonly RelayDelivery[]>;
    acknowledge(recipientId: string, deliveryId: string): Promise<void>;
    putBlob(blob: RelayBlob): Promise<void>;
    getBlob(id: string): Promise<RelayBlob | undefined>;
    pruneInactiveTopics(olderThan: number): Promise<PruneResult>;
}
```

`RelayService` handles all validation, signature verification, and limits, so a
store only needs to be correct about atomicity. `publish`, `addSubscription`,
and `consumeQueueRequest` must each be atomic — `consumeQueueRequest` is the
replay guard, and a non-atomic implementation silently removes it.
