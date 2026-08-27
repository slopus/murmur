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

An account-targeted delivery includes exact account keys and source roster
revisions. A `409 stale_roster` response includes the relay's current roster so
the sender can durably retarget and retry. Deliveries with no account targets
retain pure exact-inbox semantics.

Every delivery carries `senderAccount`, the account that owns its pending
outbound relay state. For a device sender, the relay verifies current roster
membership. Session deliveries additionally carry nullable `ownerAccount` and
`sessionId` fields. They must either both be null or both identify the immutable
session owner and exact 32-byte MLS group ID.

## `POST /v1/sessions/delete`

Accepts an account-identity-signed, recipientless delivery whose ciphertext is
`{ version: 1, type: "delete_session", sessionId }`. The relay replay-protects
the delivery operation ID and durably removes all pending deliveries tagged
with that exact sender account and session ID. Affected inbox continuity
generations advance. Success returns `{ removed }`; replay returns `409`.

## `POST /v1/accounts/delete`

Accepts an account-identity-signed, recipientless delivery whose ciphertext is
`{ version: 1, type: "delete_account" }`. In one transaction the relay removes
the account's directory pools and history, roster and roster nonces, device
inboxes and continuity state, raw session-deletion nonces, and every pending
outbound delivery whose signed `senderAccount` is that account. Surviving shared
delivery references and global counters remain exact.

Success is always `{ deleted: true }` for a valid first request, including when
the account had no state, so the route is not an existence oracle. A request-ID
replay returns `409`; its tombstone stores only a SHA-256 account digest.

## `POST /v1/device-rosters/read`

Accepts `{ accountKey }` for one exact public account identity. Returns the
current roster, including its revision, active device keys, reset generations,
latest relay session-token issuance times, owner-encrypted metadata, and current
MLS admission KeyPackages, or `404` when no roster exists. Encrypted metadata is
opaque base64url with a 16 KiB decoded limit. Access-time updates are monotonic
and do not advance roster revision.

Connected WebSocket and SSE streams receive `device_roster_changed` with the
exact account key after any roster or access-time change affecting their
account. This is an ephemeral invalidation only. Clients read the current roster
before displaying or acting on the change.

## `POST /v1/device-rosters/mutate`

Accepts an account-identity-signed ordinary delivery whose ciphertext is one
strict register, metadata-update, or remove mutation. Registration requires
opaque encrypted metadata. Metadata update replaces only those bytes and must
name the current reset generation; it does not rotate MLS admission material or
delete directory prekeys. The relay replay-protects the mutation and atomically
commits both the current roster and the notification queued to every
post-mutation device inbox. Success returns the resulting roster.

## `POST /v1/directory/upload`

Accepts an account-identity-signed, recipientless delivery whose ciphertext is
one strict per-device directory upload. `rotate` replaces the device's active
one-use pool and last-resort KeyPackage. `replenish` appends fresh one-use
packages and must name the current last-resort reference. The device must be in
the current roster with the named reset generation.

Every one-use package includes a device-signed delivery addressed to that same
device. The relay validates this pre-authorized spent notice during upload and
publishes it atomically when the package is claimed. Operation IDs and retired
package references are replay-protected. Exact active material may be
reasserted after an ambiguous response, but never changed under its reference.
Success returns `{ uploaded: true }`.

## `POST /v1/directory/claim`

Accepts `{ version: 1, accountKey, ticket }`, where the exact Ed25519 account
key and opaque authentication ticket are base64url. The configured verifier
authenticates issuer and expiry; storage atomically accounts the ticket's claim
budget and returns one admission for every current device:

```ts
interface DirectoryClaimResponse {
    version: 1;
    accountKey: string;
    rosterRevision: number;
    devices: readonly {
        deviceKey: string;
        resetGeneration: number;
        keyPackage: string;
        source: "one_time" | "last_resort";
    }[];
}
```

One-use packages are consumed. Last-resort packages are reusable and returned
only when that device has no unexpired one-use package. An unknown exact account
returns the same envelope with revision zero and an empty device array while
still spending a ticket use. The API has no enumeration operation.

Directory upload and claim requests are exempt from the relay's generic
address limiter and remote-address requirement. Directory admission control
belongs at ticket issuance; queue quotas still bound atomic spent notices.

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
- `409` cursor, acknowledgement, replay, prekey-reference, reset-generation, or
  stale-roster conflict;
- `413` request, ciphertext, recipient set, or response head exceeds a bound;
- `429` sender, recipient, ingress-principal, or address-rate quota exceeded;
- `503` global storage pressure or unavailable backing state.

Production proxies must preserve request bodies exactly, provide the configured
remote-address header when used, and enforce trusted non-Sybil ingress before
assigning an admission principal. Production directory deployments must supply
an authentication-server `DirectoryTicketVerifier`; the bundled local issuer is
for tests and local operation.
