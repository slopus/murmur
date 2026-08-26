# Relay HTTP API

The standalone relay accepts canonical JSON over HTTPS. Successful and error
responses use `cache-control: no-store`. Request JSON rejects duplicate keys,
unknown fields, malformed base64url, and noncanonical identities.

## `GET /health`

Returns `200` only after storage and the wake source are ready.

## `POST /v1/deliveries`

Accepts one signed delivery JSON object. A trusted ingress principal supplies
the admission identity used for outstanding-fanout quotas. Success returns:

```ts
interface PublishResponse {
    eventId: string;
    duplicate: boolean;
}
```

## `POST /v1/queue/read`

Accepts a signed queue-read request and returns:

```ts
interface QueuePageResponse {
    deliveries: readonly {
        eventId: string;
        sequence: number;
        delivery: unknown;
    }[];
    head: string | null;
    headSequence: number;
    acknowledgedThrough: string | null;
    acknowledgedSequence: number;
    generation: string;
    exhausted: boolean;
}
```

The `after` cursor is exclusive. `limit` and encoded response bytes are bounded.
Long polling rechecks after registration so publication cannot be missed.

## `POST /v1/queue/events`

Authenticates the same signed read and streams Server-Sent Events. The stream
begins with continuity metadata, then carries exact ordered delivery records and
periodic heartbeats. Processing does not acknowledge data.

## `POST /v1/queue/ack`

Accepts a signed recipient acknowledgement through one UUIDv7 event ID. Success
returns removed count, acknowledged sequence, and continuity generation.
Regressing or future acknowledgements fail closed.

## Common status codes

- `400` malformed or noncanonical input;
- `401` invalid identity, signature, time, or recipient authorization;
- `409` cursor or acknowledgement continuity conflict;
- `413` request, ciphertext, recipient set, or response head exceeds a bound;
- `429` sender, recipient, ingress-principal, or address-rate quota exceeded;
- `503` global storage pressure or unavailable backing state.

Production proxies must preserve request bodies exactly, provide the configured
remote-address header when used, and enforce trusted non-Sybil ingress before
assigning an admission principal.
