# Relay HTTP API

The relay accepts canonical JSON over HTTPS. Binary fields are unpadded
base64url. Timestamps are integer Unix milliseconds. Event cursors are
lowercase canonical UUIDv7 strings.

The standalone Node host speaks plain HTTP and must be placed behind trusted TLS
termination in production.

## `GET /health`

Returns `200` when the configured store is reachable.

## `POST /v1/deliveries`

Publishes one atomic encrypted multicast:

```ts
interface SignedDeliveryJson {
    version: 1;
    id: string;
    sender: string;
    recipients: readonly string[];
    createdAt: number;
    expiresAt: number;
    ciphertext: string;
    signature: string;
}
```

Recipients must be sorted, unique canonical Ed25519 identity points. The relay
verifies the sender signature, time policy, fanout, ciphertext size, per-inbox
quota, per-sender item/byte/reference quota, and global quota in one
transaction. Success returns:

```json
{ "eventId": "019...", "duplicate": false }
```

The same sender and delivery ID is idempotent while the delivery or any queue
reference remains. Reusing that ID with different signed content is rejected.

## `POST /v1/queue/read`

Reads or long-polls one identity queue:

```ts
interface SignedQueueReadJson {
    version: 1;
    recipient: string;
    after: string | null;
    limit: number;
    waitMilliseconds: number;
    createdAt: number;
    signature: string;
}
```

The signature is domain-separated and binds every field. A successful response
contains:

```ts
interface InboxPageJson {
    deliveries: readonly {
        eventId: string;
        delivery: SignedDeliveryJson;
    }[];
    head: string | null;
    acknowledgedThrough: string | null;
    exhausted: boolean;
}
```

Event IDs increase lexicographically within this inbox. They are not a global
group order. Reads exclude expired deliveries without requiring destructive
cleanup in the read transaction.

## `POST /v1/queue/ack`

Trims one durably processed prefix:

```ts
interface SignedQueueAckJson {
    version: 1;
    recipient: string;
    through: string;
    createdAt: number;
    signature: string;
}
```

Acknowledgement must not regress or exceed the inbox head. It removes queue
references through `through`, deletes orphan deliveries, updates exact pending
counters, and reclaims empty inbox metadata.

## Errors and admission

Responses use stable JSON error codes. Important classes include:

- `400` malformed or invalid signed input;
- `401` authentication or time-policy failure;
- `409` cursor/acknowledgement conflict;
- `413` encoded body or delivery limit;
- `429` recipient, sender, or admitted-principal queue backpressure;
- `503` global queue backpressure, missing admission context, or overload.

Signed reads and acknowledgements are reusable inside their short clock-skew
window. TLS and ingress admission are mandatory. The bundled host's
per-address limiter is only a local safety bound; it is not Sybil resistance.
A public deployment must admit a non-Sybil principal at a trusted ingress and
budget that principal's outstanding fanout before forwarding. The bundled host
uses the socket peer address unless a trusted, overwritten admission header is
configured. Direct `RelayService.publish` calls also require an explicit
principal; disabling HTTP address admission requires one explicit shared
`defaultAdmissionPrincipal`.
