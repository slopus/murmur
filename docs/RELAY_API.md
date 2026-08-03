# Relay HTTP API

`@murmur/relay` exposes a fixed, credential-free HTTP protocol for signed topic
state and short-lived blob-transfer links. It is implemented by
`createRelayFetchHandler`; `HttpRelayTransport` is the browser-safe client
implementation.

There are no subscription, recipient, queue-pull, or acknowledgement routes.
Clients read topics directly using their locally stored cursors.

Two routes carry traffic the relay never stores: `POST .../ephemeral` and
`GET .../stream`. They add no durable state and no message semantics — the
relay still cannot tell an ephemeral frame from any other opaque bytes.

## Conventions

- JSON requests and responses use UTF-8.
- All byte strings are unpadded, canonical base64url.
- Relay sequences and versions are decimal strings in JSON because they are
  stored as `bigint`.
- Timestamps are non-negative integer milliseconds since the Unix epoch.
- Topic IDs use `[A-Za-z0-9_.:-]`, length 1 through 512.
- List element IDs use the same alphabet, length 1 through 256.
- Event IDs and blob IDs are canonical base64url encodings of 32 bytes
  (43 characters).
- Unknown routes and unknown topic/blob resources return
  `{"error":"not_found"}` with HTTP 404.
- CORS defaults to `Access-Control-Allow-Origin: *`. An explicit origin list
  returns the requesting allowed origin and `Vary: Origin`.

Event signatures use Ed25519 over recursively key-sorted canonical JSON with
the `signature` member omitted. The full event shape is in
[PROTOCOL.md](PROTOCOL.md#relay-events).

## Endpoints

### `GET /`

Returns a human-readable relay identity with HTTP 200:

```text
Welcome to Murmur Relay!
```

### `GET /health`

Checks whether the backing `RelayStore` can run its health query.

```json
{ "ok": true }
```

Returns HTTP 200 on success. It is a read-rate-limited endpoint.

### `POST /v1/topics/:topic/events`

Validates, authenticates, and atomically applies a signed event. The route
topic must exactly equal the signed event's `topic`.

Request body:

```ts
{
    version: 1,
    id: string,
    topic: string,
    author: { signingKey: string },
    createdAt: number,
    payload: string,
    snapshot?: {
        expectedVersion: number,
        bytes?: string,
    },
    list?: readonly (
        | { op: "append"; id: string; bytes: string }
        | { op: "replace"; id: string; expectedVersion?: number; bytes: string }
        | { op: "delete"; id: string; expectedVersion?: number }
    )[],
    signature: string,
}
```

`snapshot.bytes` absent means delete the snapshot. For a snapshot mutation,
`expectedVersion: 0` means no snapshot must currently exist; otherwise the
version must match. Appending an existing list ID, or replacing/deleting a
missing element or a mismatched expected version, is a conflict.

Successful response, HTTP 200:

```ts
{
    seq: string,
    duplicate: boolean,
    snapshotVersion?: string,
}
```

The first accepted publish returns `duplicate: false`. Retrying the exact same
`(topic, id)` returns the original sequence and `duplicate: true`, even after
event retention has expired. Reusing the ID for different signed content
returns:

```json
{ "error": "id_collision" }
```

An optimistic-concurrency conflict returns HTTP 409:

```ts
{
    error: "conflict",
    snapshotVersion: string,
    elements: Record<string, string>,
}
```

`elements` contains the current version, or `"0"`, for every list element
touched by the event.

The relay accepts event timestamps only within five minutes before or after its
current clock. It applies the publish cost to the request IP and, after a
valid event signature, to `author.signingKey`.

### `GET /v1/topics/:topic/state?limit=N`

Reads a transactionally consistent topic head, optional snapshot, and first
ordered list page. `limit` defaults to 256 and may not exceed the configured
list-page maximum.

HTTP 200:

```ts
{
    seq: string,
    snapshot: {
        version: string,
        bytes: string,
    } | null,
    list: {
        elements: readonly {
            id: string,
            version: string,
            bytes: string,
        }[],
        nextCursor: string | null,
    },
}
```

Use `nextCursor` with the list endpoint until it is `null`. `seq` is the head
to install after the complete state is durably applied. An absent topic returns
HTTP 404.

### `GET /v1/topics/:topic/list?cursor=C&limit=N`

Reads a later page of the current permanent ordered list. `cursor` is an opaque
cursor returned by the preceding state or list response; omit it for the first
page. `limit` has the same default and maximum as the state endpoint.

HTTP 200:

```ts
{
    elements: readonly {
        id: string,
        version: string,
        bytes: string,
    }[],
    nextCursor: string | null,
}
```

The list endpoint does not return a topic head because it is a page
continuation. A topic that disappears while a client paginates returns HTTP
404; `MurmurClient.loadTopic()` treats that as a failed load.

### `GET /v1/topics/:topic/events?since=S&limit=N&wait=MS`

Reads retained events strictly after `since`.

| Query   | Default | Meaning                                                                             |
| ------- | ------- | ----------------------------------------------------------------------------------- |
| `since` | `0`     | Decimal topic sequence already durably processed.                                   |
| `limit` | `256`   | Maximum retained events to return; cannot exceed the configured event-page maximum. |
| `wait`  | `0`     | Long-poll milliseconds. It cannot exceed the configured maximum or 30,000 ms.       |

HTTP 200:

```ts
{
    events: readonly ({
        seq: string,
        version: 1,
        id: string,
        topic: string,
        author: { signingKey: string },
        createdAt: number,
        payload: string,
        snapshot?: { expectedVersion: number, bytes?: string },
        list?: readonly (
            | { op: "append", id: string, bytes: string }
            | { op: "replace", id: string, expectedVersion?: number, bytes: string }
            | { op: "delete", id: string, expectedVersion?: number }
        )[],
        signature: string,
    })[],
    reset: boolean,
    seq: string, // current topic head
}
```

`reset: false` means every returned event is a retained successor of `since`.
If `reset: true`, `events` is empty and `since` is unusable: it is older than
the retained window or greater than the current topic head. The client must
reload state and the full list rather than treating the response as caught up.

An empty `events` array with `reset: false` means no retained successor was
available at the time of the read. With `wait`, the relay may park until a
publish wake or the timeout, then re-read. Long-poll capacity exhaustion
returns HTTP 503 with `{"error":"overloaded"}`.

### `POST /v1/topics/:topic/ephemeral`

Delivers opaque bytes to the topic's current stream subscribers **without
storing anything**. There is no receipt, sequence, idempotency, signature
check, or topic-existence check, the relay does not parse the body, and topic
activity is not refreshed. The request body is raw bytes.
`content-type: application/octet-stream` is the convention; the relay never
inspects the header and treats the body as opaque bytes whatever it says or
omits.

HTTP 200:

```ts
{
    delivered: number,
}
```

`delivered` counts the stream subscribers on **this relay instance** that the
frame was enqueued for. It is informational and never a delivery guarantee.
Frame fan-out is deliberately in-process: `EphemeralFanout` is an extension
interface, and the default `InProcessEphemeralFanout` does not reach other
instances.

A body above `maximumEphemeralFrameBytes` returns HTTP 413 `{"error":"limit"}`.

The route is charged to the request IP only, and its cost scales with the
fan-out it causes: `rateLimit.costs.ephemeral` for the request, plus
`rateLimit.costs.ephemeral` for each stream subscriber of the topic. One cheap
POST therefore cannot buy an unbounded number of enqueues. The fan-out share is
charged from the subscriber count read immediately before delivery, so an
over-budget publisher receives HTTP 429 **instead of** the fan-out rather than
after it, and it is clamped to the bucket capacity so `Retry-After` stays
finite. Nothing is charged when the topic has no subscribers.

### `GET /v1/topics/:topic/stream`

Opens a `text/event-stream` for prompt delivery. This is the low-latency
counterpart to the 30-second long poll: it exists so a client does not have to
choose between a stored event and a timely one.

Named events, each carrying one line of `data`:

| event   | data                          | meaning                                      |
| ------- | ----------------------------- | -------------------------------------------- |
| `ready` | `{"topic":"<topic>"}`         | the stream is live; always sent first        |
| `frame` | base64url of the opaque bytes | one ephemeral frame                          |
| `wake`  | `{}`                          | durable events may be available; sync now    |
| `drop`  | `{"frames":<n>}`              | the relay dropped `n` frames for this reader |

A `: keepalive` comment is written whenever
`streamKeepAliveMilliseconds` elapses without traffic. The stream ends when the
client aborts the request or the service closes.

`wake` is driven by the same signals that already wake long polls — a local
publish plus `WakeSource.subscribe` — so it keeps working across instances and
makes durable publishes prompt too.

Each subscriber has a bounded, drop-oldest queue of at most
`maximumStreamQueueFrames` frames and `maximumStreamQueueBytes` bytes; overflow
drops the **oldest** frames and emits one coalesced `drop`. At most one `wake`
is pending per subscriber. The body is pull-driven, so a reader that stops
reading cannot make the relay accumulate memory without bound: one `pull`
drains the queue and enqueues what it drained, and the producer can refill the
queue behind it, so peak buffering per stalled subscriber is roughly twice
`maximumStreamQueueBytes`.

Those per-subscriber bounds multiplied by `maximumConcurrentStreams` promise far
more memory than a relay has, so retention is bounded in aggregate as well.
`maximumTotalStreamQueueBytes` (64 MiB by default) is the ceiling on ephemeral
frame bytes one process holds at any moment, counting both queued frames and the
batch a reader has already been handed but not yet come back from. Exceeding it
drops the oldest frames of whichever reader has been backlogged longest, and
that reader is told with the same coalesced `drop` event as a per-subscriber
overflow, so the path degrades instead of refusing service. Readers that drain
and return are the last to lose anything. The copy in flight is base64-encoded,
so bytes on the wire are about 4/3 of the frame bytes counted here.

The route returns HTTP 503 `{"error":"overloaded"}` beyond either subscriber
ceiling: `maximumConcurrentStreams` per process and `maximumStreamsPerTopic` per
topic. The per-topic ceiling matters because this route is unauthenticated and
billed as an ordinary read; without it one client could hold every process-wide
slot on a single topic. Streams have no server-imposed lifetime, so a client
that wants to release a slot must close the connection.

### `POST /v1/blobs/:id/upload-link`

Requests a short-lived upload link for a content-addressed ciphertext blob.
There is no request body.

HTTP 200:

```ts
{
    url: string,
    method: "PUT",
    expiresAt: number,
    headers?: Readonly<Record<string, string>>,
}
```

For the local backend, `url` is a **relative** relay URL and `headers` includes
`content-type: application/octet-stream`. For the S3 backend, `url` is an
absolute SigV4 presigned URL and headers include the signed
`x-amz-checksum-sha256` value. The client must use the returned method, URL,
and headers.

This endpoint and a local signed `PUT` both use the upload rate-limit cost.
If no blob backend was configured, it returns HTTP 503
`{"error":"blob_unavailable"}`.

### `POST /v1/blobs/:id/download-link`

Requests a short-lived download link. There is no request body.

HTTP 200:

```ts
{
    url: string,
    method: "GET",
    expiresAt: number,
    headers?: Readonly<Record<string, string>>,
}
```

The relative-local versus absolute-S3 rule is the same as for upload links. A
missing blob returns HTTP 404. The request has the read rate-limit cost.

For S3, the backend performs a signed `HEAD` request before issuing a `GET`
link. The relay receives that metadata check, but not the download bytes.

### Local signed transfer route: `PUT` or `GET /v1/blobs/:id`

This route is **not** a general blob API. It exists only when the configured
backend is `LocalBlobBackend`, and only for the signed relative URL returned by
one of the two link endpoints.

The URL must contain exactly one `expires` and one `signature` query parameter.
The HMAC authenticates the version, method, blob ID, and expiry. A malformed,
expired, wrong-method, or bad-signature link returns HTTP 401 with either
`{"error":"unauthorized"}` or `{"error":"expired"}`.

- Signed `PUT` streams raw ciphertext and returns HTTP 204 after its SHA-256
  matches `:id`. A size excess returns HTTP 413; a hash mismatch returns HTTP
  400 `{"error":"hash_mismatch"}`.
- Signed `GET` returns raw `application/octet-stream` bytes with HTTP 200, or
  HTTP 404 if the installed file is absent.

With the S3 backend, these relay-local methods return 404 because the returned
link is an S3 URL. An unsigned direct `PUT` or `GET` should not be used.

### `OPTIONS /*`

Returns HTTP 204 with the configured CORS headers. The allowed methods are
`GET, POST, PUT, OPTIONS`; allowed request headers are `Content-Type` and
`Content-Length`.

## Status codes and error bodies

| Status | Body / condition                                                                                                                                                                       |
| ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 200    | Successful JSON read, publish, health check, or issued blob link; local blob `GET` also returns raw bytes.                                                                             |
| 204    | CORS preflight or successful local blob upload.                                                                                                                                        |
| 400    | `{"error":"malformed"}` for invalid JSON, fields, path/query parameters, cursor, or `Content-Length`; `hash_mismatch` for a valid signed local upload whose bytes do not match its ID. |
| 401    | `{"error":"unauthorized"}` for invalid event signatures, expired event timestamps, or invalid local blob links; `{"error":"expired"}` for an expired local blob link.                  |
| 404    | `{"error":"not_found"}` for an unknown route, topic, blob, or S3-mode local transfer route.                                                                                            |
| 409    | `{"error":"id_collision"}` for different content under an existing event/blob ID, or the structured `conflict` body for state concurrency failure.                                     |
| 413    | `{"error":"limit"}` when a configured request, event, state mutation, list, or blob bound is exceeded.                                                                                 |
| 429    | `{"error":"rate_limited","retryAfterMilliseconds":number}` plus `Retry-After` in seconds.                                                                                              |
| 500    | `{"error":"internal"}` for unexpected handler or backend errors.                                                                                                                       |
| 503    | `{"error":"overloaded"}` when the long-poll or a stream-subscriber cap is reached, or `{"error":"blob_unavailable"}` when links are requested without a backend.                       |

## Default limits

`RelayOptions` controls relay policy. `RelayHttpOptions.maximumPageResponseBytes`
controls the HTTP page budget separately.

| Limit                         |            Default | Notes                                                                                                |
| ----------------------------- | -----------------: | ---------------------------------------------------------------------------------------------------- |
| Event payload                 |              1 MiB | Opaque `payload` bytes before JSON encoding.                                                         |
| Snapshot mutation             |              4 MiB | Current snapshot bytes.                                                                              |
| One list element mutation     |            256 KiB | Append or replace bytes.                                                                             |
| List operations per event     |                256 | Atomic operations, in supplied order.                                                                |
| Live list elements per topic  |            100,000 | Checked in the publish transaction.                                                                  |
| Blob bytes                    |             64 MiB | Applied to local transfers.                                                                          |
| JSON request body             |              8 MiB | Bound while streaming the request.                                                                   |
| Events per read               |                256 | Applies to `GET events`.                                                                             |
| List elements per page        |                256 | Applies to state/list reads.                                                                         |
| Event/list HTTP page response |              8 MiB | An available oversized first item is still returned so pagination cannot stall.                      |
| Long-poll wait                |               30 s | Hard maximum; lower configuration is allowed.                                                        |
| Concurrent long polls         | 10,000 per process | Beyond it, reads return 503.                                                                         |
| Ephemeral frame               |            128 KiB | `maximumEphemeralFrameBytes`; nothing is stored.                                                     |
| Concurrent streams            | 10,000 per process | `maximumConcurrentStreams`; beyond it, the stream route returns 503.                                 |
| Streams per topic             |    256 per process | `maximumStreamsPerTopic`; beyond it, the stream route returns 503.                                   |
| Stream queue                  |   64 frames, 1 MiB | `maximumStreamQueueFrames`/`maximumStreamQueueBytes`, per subscriber, drop-oldest.                   |
| Stream retention, all streams |             64 MiB | `maximumTotalStreamQueueBytes`; the hard process-wide ceiling, queued plus in flight, drop-oldest.   |
| Stream keepalive              |               15 s | `streamKeepAliveMilliseconds`; comment written after an idle interval.                               |
| Event retention               |             7 days | Only event bodies expire.                                                                            |
| Topic inactivity              |            30 days | Measured from successful publish; dropping a topic removes its snapshot, list, events, and receipts. |
| Event clock skew              |         ±5 minutes | Validated after signature and receipt lookup.                                                        |
| Local blob-link lifetime      |          5 minutes | Backend construction option.                                                                         |
| S3 presigned-link lifetime    |          5 minutes | Backend construction option, allowed range 1 through 604,800 seconds.                                |
| Token bucket capacity         |              1,000 | Per key, per process.                                                                                |
| Token refill                  |        50 tokens/s | Per key, per process.                                                                                |
| Token-bucket count            |             50,000 | LRU-bounded map, per process.                                                                        |
| Publish cost                  |                 25 | Charged to IP and valid event author.                                                                |
| Ephemeral cost                |                  1 | Charged to IP once for the request and once per subscriber fanned out to.                            |
| Upload cost                   |                 10 | Upload-link and local signed upload, charged to IP.                                                  |
| Read cost                     |                  1 | All other routes, charged to IP.                                                                     |

The default rate limiter is not shared. An `N`-instance deployment has
approximately `N` times the effective default rate limit.

## Extension interfaces

### `RelayStore`

Storage backends implement this interface. `publish()` must atomically allocate
the topic sequence, apply snapshot/list mutations, write the durable receipt,
retain the event, and update last activity.

```ts
interface RelayStore {
    readPublishReceipt(topic: string, id: string): Promise<PublishReceipt | undefined>;
    publish(
        event: SignedRelayEvent,
        now: number,
        constraints: { maximumElementsPerTopic: number },
    ): Promise<PublishOutcome>;
    readState(
        topic: string,
        limit: number,
        constraints: { maximumEncodedBytes: number },
    ): Promise<TopicState | undefined>;
    readList(
        topic: string,
        cursor: string | undefined,
        limit: number,
        constraints: { maximumEncodedBytes: number },
    ): Promise<ListPage | undefined>;
    readEvents(
        topic: string,
        since: bigint,
        limit: number,
        constraints: { maximumEncodedBytes: number },
    ): Promise<EventPage | undefined>;
    pruneEvents(olderThan: number): Promise<number>;
    pruneInactiveTopics(olderThan: number): Promise<{ topics: number }>;
    health(): Promise<void>;
    close(): Promise<void>;
}
```

The `TopicState` result contains the head sequence, optional current snapshot,
and one list page. `EventPage` contains `events`, `reset`, and current head
`seq`. `PublishOutcome` contains `seq`, `duplicate`, and optionally
`snapshotVersion`.

### `BlobBackend`

```ts
interface BlobLink {
    readonly url: string;
    readonly method: "PUT" | "GET";
    readonly expiresAt: number;
    readonly headers?: Readonly<Record<string, string>>;
}

interface BlobBackend {
    createUploadLink(id: string, now: number): Promise<BlobLink>;
    createDownloadLink(id: string, now: number): Promise<BlobLink | undefined>;
    handleTransfer?(
        request: Request,
        id: string,
        now: number,
        maximumBytes: number,
    ): Promise<Response>;
    close(): Promise<void>;
}
```

A backend that returns relay-local links implements `handleTransfer`. A backend
such as S3 returns an absolute URL and omits it.

### `RateLimiter`

```ts
interface RateLimitDecision {
    readonly allowed: boolean;
    readonly retryAfterMilliseconds: number;
}

interface RateLimiter {
    consume(key: string, cost: number, now: number): Promise<RateLimitDecision>;
}
```

Pass one through `RelayHttpOptions.rateLimiter` to replace the in-memory token
bucket with a shared implementation.

### `EphemeralFanout`

```ts
interface EphemeralFanout {
    subscribe(topic: string): EphemeralSubscription | undefined;
    publishFrame(topic: string, frame: Uint8Array): number;
    wake(topic: string): void;
    readonly subscriberCount: number;
    subscriberCountForTopic(topic: string): number;
    close(): void;
}
```

`subscribe()` returns `undefined` once `maximumConcurrentStreams` or
`maximumStreamsPerTopic` is reached. `subscriberCountForTopic()` is what the
HTTP boundary prices a fan-out from before publishing it. The interface is
synchronous because frame fan-out is in-process by design, which keeps
`delivered` exact. Pass an implementation as the fifth `RelayService`
constructor argument to substitute a shared bus later; `wake` already crosses
instances through `WakeSource`.

### `WakeSource`

```ts
interface WakeSource {
    notify(topic: string): Promise<void>;
    subscribe(listener: (topic: string) => void): Promise<void>;
    close(): Promise<void>;
}
```

Wake sources affect long-poll latency, not correctness. `InProcessWakeSource`
is appropriate for SQLite's one-process deployment. `PostgresWakeSource`
receives the notifications emitted transactionally by `PostgresRelayStore`.
