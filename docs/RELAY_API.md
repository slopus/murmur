# Relay HTTP API

The relay accepts canonical JSON over HTTPS for queue operations. Invitation
upload and download use the exact canonical discovery-bundle bytes. Binary
fields inside JSON are unpadded base64url. Timestamps are integer Unix
milliseconds. Event cursors are lowercase canonical UUIDv7 strings.

The standalone Node host speaks plain HTTP and must be placed behind trusted TLS
termination in production.

## `GET /health`

Returns `200` when the configured store is reachable.

## `POST /v1/invitations`

Uploads the exact canonical bytes returned by
`serializeDiscoveryBundle()`, using
`content-type: application/vnd.slopus.murmur-discovery+json`.

The relay reads only `createdAt` and `expiresAt` to enforce its retention
policy. It does not authenticate or trust the remaining public bundle; the
recipient performs complete verification. The signed lifetime and remaining
relay lifetime must both be no more than five minutes.

Success returns:

```ts
interface InvitationUploadJson {
    digest: string; // base64url SHA-256, 32 decoded bytes
    expiresAt: number;
    duplicate: boolean;
}
```

Re-uploading identical bytes is idempotent and never extends their original
expiry unless a live revocation tombstone exists, in which case the relay
returns `410 invitation_revoked`. This compatibility route does not register
revocation authority; new Murmur clients use the owner-authorized route below.

## `POST /v1/invitations/owned`

Registers one exact invitation with a separate revocation public key:

```ts
interface OwnedInvitationUploadJson {
    version: 1;
    bundle: string; // base64url exact canonical discovery bytes
    authorization: {
        version: 1;
        owner: string; // canonical 32-byte Ed25519 invitation identity
        revocationKey: string; // canonical 32-byte Ed25519 public key
        digest: string; // SHA-256 of bundle
        expiresAt: number; // exact signed bundle expiry
        createdAt: number;
        signature: string; // 64-byte Ed25519 signature by owner
    };
}
```

The owner signature covers `"murmur.relay.invitation-upload.v1\0"` followed by
canonical JSON of every authorization field except `signature`. The relay also
checks the bundle's claimed identity, digest, expiry, authorization clock skew,
and canonical public keys. Success returns `InvitationUploadJson` from the
legacy route. An exact row uploaded first through the compatibility route may
be upgraded idempotently by its owner; a conflicting authority is rejected.

The private revocation key is never transmitted. The public key and
authorization are cache metadata, not part of the invitation recipients fetch.

## `POST /v1/invitations/revoke`

Revokes one invitation, or every unexpired invitation registered under one
authority:

```ts
interface SignedInvitationRevocationJson {
    version: 1;
    revocationKey: string;
    digest: string | null; // null means all rows for this authority
    createdAt: number;
    signature: string;
}
```

The signature covers `"murmur.relay.invitation-revocation.v1\0"` followed by
canonical JSON of every field except `signature`. It must fall within the
configured authentication-skew window. Success returns `{ "revoked": number }`.
Client redemption creates no relay state, so revocation remains valid after a
matching private KeyPackage was consumed. Missing, expired, and already
revoked rows are idempotent and return zero when no live cache row changed. A
live row or tombstone registered to another authority returns
`401 invitation_revocation_unauthorized`.

Revocation atomically replaces each live row with a tombstone under its exact
digest and original expiry. The tombstone blocks re-upload resurrection, counts
toward item and admission bounds, and is pruned at expiry. Each authority-wide
scan page is capped by `maximumInvitationItemsPerRevocationKey` (32 by default),
including when a lower runtime bound must drain rows admitted under an earlier
configuration.

## `GET /v1/invitations/:digest`

Returns the exact unexpired discovery-bundle bytes addressed by one canonical
base64url SHA-256 digest. There is no listing, identity lookup, prefix lookup,
or alternate address. Missing and expired digests return
`404 invitation_not_found`.

Revoked digests use the same `404 invitation_not_found` response and reveal no
bundle bytes.

Clients must compare SHA-256 of the response with the shared digest before
parsing, then verify the signed expiry, identity signature, and KeyPackages.

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
        sequence: number;
        delivery: SignedDeliveryJson;
    }[];
    head: string | null;
    headSequence: number;
    acknowledgedThrough: string | null;
    acknowledgedSequence: number;
    generation: string; // canonical base64url, exactly 32 bytes
    exhausted: boolean;
}
```

Event IDs increase lexicographically within this inbox. They are not a global
group order. Reads exclude expired deliveries without requiring destructive
cleanup in the read transaction.

## `POST /v1/queue/events`

Opens one recipient-authenticated SSE response using the same
`SignedQueueReadJson` body with `waitMilliseconds: 0` and `limit: 1`. The
response is `text/event-stream`; it emits exact queued deliveries:

```text
event: continuity
data: {"generation":"...","head":"019...","headSequence":4,"acknowledgedThrough":null,"acknowledgedSequence":0}

id: 019...
event: delivery
data: {"eventId":"019...","sequence":4,"delivery":{...SignedDeliveryJson}}

```

Records are pull-driven and ordered by UUIDv7 within this inbox. `: keepalive`
comments prevent idle intermediary timeouts and do not represent queue
progress. The stream's in-memory cursor advances through emitted records, while
the durable recipient cursor advances only through signed acknowledgement.
Reconnect with a freshly signed request whose `after` is the durable cursor.
Unacknowledged records may therefore be redelivered.

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
counters, and returns `{removed, sequence, generation}`. Empty inbox metadata
is retained. Expiry of any unacknowledged reference advances its inbox's
generation; acknowledgement never does. The hard retention window is exactly
180 days.

## Errors and admission

Responses use stable JSON error codes. Important classes include:

- `400` malformed or invalid signed input;
- `401` authentication or time-policy failure;
- `409` cursor/acknowledgement conflict;
- `410 invitation_revoked` when public bytes try to resurrect a live
  revocation tombstone;
- `413` encoded body or delivery limit;
- `429` recipient, sender, admitted-principal queue, or per-principal
  invitation-cache backpressure;
- `503` global queue or invitation-cache backpressure, missing admission
  context, or overload.

Signed reads and acknowledgements are reusable inside their short clock-skew
window. TLS and ingress admission are mandatory. The bundled host's
per-address limiter is only a local safety bound; it is not Sybil resistance.
A public deployment must admit a non-Sybil principal at a trusted ingress and
budget that principal's outstanding fanout before forwarding. The bundled host
uses the socket peer address unless a trusted, overwritten admission header is
configured. Direct `RelayService.publish` calls also require an explicit
principal; disabling HTTP address admission requires one explicit shared
`defaultAdmissionPrincipal`.
