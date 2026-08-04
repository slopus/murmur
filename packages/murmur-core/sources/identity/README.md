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
an ID with different content throws a typed collision error. Optional callbacks
let applications persist an outgoing envelope in their outbox within the same
transaction as the state transition.

## Friend channel

After acceptance, `FriendChannel` derives one shared encryption key and one
opaque topic authorization key from X25519 agreement over the peers' single
identity keys. It carries only opaque durable or expiring control bytes, such
as profile changes, friendship termination, or a later MLS Welcome.

Control payloads are AES-GCM encrypted with the shared channel key and also
Ed25519-signed by their individual sender. `acceptFriendControl` commits an
application effect and replay marker atomically. Normal two-person and
multi-person conversation data belongs to MLS, not this channel.
