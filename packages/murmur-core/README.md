# `@slopus/murmur`

Browser-safe primitives for stateful end-to-end encrypted communication over a
deliberately dumb relay. Applications provide `MurmurStore`; Murmur owns
identity, friendship, synchronization, and MLS state.

This is a clean `0.x` rewrite. It intentionally has no compatibility codecs or
migrations for earlier identity, direct-message, list, snapshot, CLI, or
multi-relay APIs.

## Identity

An identity has one 32-byte root secret and exposes one 32-byte Ed25519 public
key:

```ts
import { generateIdentityKeyPair, serializePublicIdentity } from "@slopus/murmur";

const identity = generateIdentityKeyPair();
const publicIdentity = serializePublicIdentity(identity);
// { publicKey: "..." }
```

Signing uses Ed25519. Pairwise encryption and key agreement convert the same
root/public point to X25519 with Noble. This is deliberate composition with the
theoretical risk documented in the friends plan; Ed25519 and X25519 encodings
are never represented as interchangeable raw bytes.

## Friendship

`FriendBook` implements the durable request/response lifecycle. A request seals
the sender identity, authenticated profile, opaque response address, and
optional application bytes to the recipient. Receiving it creates
`pending-incoming`, not an active friend. Only an authenticated accepted
response establishes `active`.

```ts
import { FriendBook, MemoryMurmurStore, generateIdentityKeyPair } from "@slopus/murmur";

const alice = generateIdentityKeyPair();
const bob = generateIdentityKeyPair();
const aliceFriends = new FriendBook(alice, new MemoryMurmurStore());
const bobFriends = new FriendBook(bob, new MemoryMurmurStore());

const request = await aliceFriends.createRequest(bob, {
    profile: { name: "Alice" },
    destination: "bob-friend-inbox",
    responseAddress: "alice-response-route",
});
await bobFriends.receiveRequest(request.envelope);

const response = await bobFriends.respond(alice, {
    decision: "accepted",
    profile: { name: "Bob" },
    responseAddress: "bob-response-route",
});
await aliceFriends.receiveResponse(bob, response.outbox.envelope);
```

Request/response replay markers and lifecycle state are committed atomically.
`FriendBook` owns exact request/response outbox items and their opaque
destinations in the same transaction. Applications publish `listOutbox()`
items and call `confirmOutbox()` only after an accepted or duplicate outcome.
Crossed requests converge through one canonical contender.

Requests after ended state carry a signed causal predecessor. `end()` retires
stale request/accept publications and durably queues either an exact rejection
or a transport-neutral friend-channel termination intent, depending on the
current lifecycle state.

## Friend control channel

`FriendChannel` is the non-MLS bootstrap/control channel available after the
two identities know each other. Both peers derive the same opaque relay topic
authorization key and message-encryption key. Payloads are opaque bytes with
durable or expiring retention and individual sender signatures.

Outer request, response, and control envelopes expose no Murmur identity IDs.
The friend channel rejects semantically expired temporary content. Its
defensive-copy topic secret export lets transport integration construct a
read/write capability without coupling this domain to relay types.

It is suitable for profile changes, friendship termination, and MLS invitation
bytes. It is not a chat protocol. Ordinary two-person and multi-person
communication uses the same MLS group primitive in the group layer.

## Security boundary

The package is ESM-only, browser-safe, side-effect free, and uses Noble for
cryptography. Secret intermediates are zeroed when their operation completes.
This pre-audit `0.x` protocol should not be treated as independently audited
cryptographic software.
