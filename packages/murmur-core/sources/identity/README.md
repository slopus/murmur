# Identity and friends

This domain implements the bootstrap before MLS. It has no relay client,
arbitrary topic string, chat message, or group semantics.

## Friend exchange

`createFriendRequest` signs an authenticated profile, an opaque response
address, and optional application bytes, then seals all of it to the
recipient's single public identity key. Only the recipient learns who sent the
request and where a response belongs.

`createFriendResponse` returns an authenticated accepted or rejected decision
bound to the original request ID and requester. An accepted response includes
the responder profile, response address, and optional private bootstrap bytes.

`FriendBook` owns the durable state machine:

```text
none/ended -> pending-outgoing -> active/ended
none/ended -> pending-incoming -> active/ended
active     -> ended
```

Inbound request/response fingerprints and lifecycle changes commit in the same
`MurmurStore` transaction. Replays return `"duplicate"`; authenticated reuse of
an ID with different content throws a typed collision error. `FriendBook` owns
an exact durable outbox: lifecycle changes never commit unless their envelope
and opaque destination commit with them. `listOutbox()` supplies publications
and `confirmOutbox()` removes only the exact accepted/duplicate item.

Simultaneous crossed requests resolve by the canonical tuple `(requester
identity ID, request ID)`. Both peers choose the same winner and atomically
retire the losing local request/outbox.

Every request authenticates `previousRequestId`. An initial request uses
`null`; a request after an ended relationship must name the durable tombstone's
`nextRequestPredecessorId`. This causal predecessor, rather than wall-clock
ordering, prevents delayed old requests from reopening ended state.

The tombstone stores this separately as nullable
`nextRequestPredecessorId`. Only a request known by both peers advances it.
Canceling an unpublished outgoing request preserves the prior predecessor, so
the other peer can still initiate with `null` (or the last mutually-known
generation) without deadlocking. The canceled `requestId` remains available
independently for late-response replay correlation.

`end()` is state-specific: it retires a pending outgoing request, queues an
exact rejection for pending incoming, or replaces stale active request/accept
publications with a durable `friendship-ended` control intent. Intents survive
restart and use the same exact `confirmOutbox()` contract after the facade seals
and publishes them.

Relay-visible request and response envelopes contain only their type,
ephemeral key, nonce, and ciphertext. Sender and recipient bindings remain
inside the signed encrypted payload.

## Friend channel

After acceptance, `FriendChannel` derives one shared encryption key and one
opaque topic authorization key from X25519 agreement over the peers' single
identity keys. It carries only opaque durable or expiring control bytes, such
as profile changes, friendship termination, or a later MLS Welcome.

Control payloads are AES-GCM encrypted with the shared channel key and also
Ed25519-signed by their individual sender. `acceptFriendControl` commits an
application effect and replay marker atomically. Normal two-person and
multi-person conversation data belongs to MLS, not this channel.

The relay-visible control envelope contains no identity. Both peers derive the
same topic public key and secret; `exportTopicSecretKey()` returns a defensive
copy which its caller must zero. An injected/default clock rejects temporary
payloads at or after `expiresAt`.

All base64url fields are length-bounded before decoding. Sensitive decoded
private/control bytes are zeroed on every failed validation, signature, expiry,
or application-persistence path.
