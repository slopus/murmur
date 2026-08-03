# HTTP API

The Fetch-compatible handler can be tested without binding a socket. It performs
strict routing, incrementally bounds JSON request bodies, applies weighted
per-IP and authenticated-author limits, converts base64url at the protocol
boundary, and serializes every bigint as a decimal string.

```text
Request -> client-IP/rate policy -> route -> RelayService or BlobBackend
```

CORS defaults to `*` and can be restricted to an explicit origin list. Event and
list encoders accumulate UTF-8 sizes and stop at the configured response budget,
while preserving the topic head or next list cursor needed to continue.
`X-Forwarded-For` is ignored by default; only an explicit hop-count or exact
proxy-address policy enables it.

The root route returns a plain-text welcome. An optional injected logger records
only named routes, methods, status codes, and durations; it never records topic
IDs, blob IDs, client IPs, payloads, or keys. Successful health probes are
suppressed.

Two routes serve the non-durable ephemeral path. `POST /v1/topics/:topic/ephemeral`
reads raw `application/octet-stream` bytes (bounded by `maximumEphemeralFrameBytes`,
413 on excess), fans them to local stream subscribers, stores nothing, and returns
`{"delivered":n}`; it carries the `costs.ephemeral` rate-limit class.
`GET /v1/topics/:topic/stream` returns a `text/event-stream` `ReadableStream`
emitting `ready`, `frame`, `wake`, and `drop` events plus `: keepalive` comments,
and returns 503 `overloaded` past `maximumConcurrentStreams`. Both are covered by
the shared CORS wrapping and the `POST`/`GET` methods already advertised on
`OPTIONS`; they are classified as `topic-ephemeral` and `topic-stream` for logging.
