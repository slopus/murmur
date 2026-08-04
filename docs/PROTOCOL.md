# Protocol

All wire and durable formats are strict, versioned, bounded, and new to this
rewrite. No prior Murmur layout is read.

## Identity and friends

One 32-byte root is an Ed25519 seed and is deliberately converted to X25519 for
key agreement. The public identity is the 32-byte Ed25519 public key.

A friend request contains the sender profile, causal request identifier, and a
random protected response address. It is identity-signed, sealed to the
recipient, then published to:

```text
{ type: "read", name: "friend-requests", readKey: recipientIdentityKey }
```

The outer relay author is fresh and unlinkable. Responses use the same inner
authentication and sealing and another fresh outer author.

Accepted friends derive an encrypted `control` channel with separate
identity-ordered send and receive AES keys plus an independently derived stable
topic key. Version-one frames are:

- profile update;
- friendship ended;
- KeyPackage announce;
- KeyPackage request;
- KeyPackage consumed acknowledgement;
- KeyPackage retirement;
- group invitation.

Temporary control retention maps exactly to relay `expiresAt`; all other
control events are durable.

## KeyPackages and invitations

Each friend pair maintains durable local private and remote public one-use
KeyPackage pools. A remote package is moved to a consumed marker in the same
transaction that stages an Add. A local bundle is consumed in the invitation
adoption transaction. Package lifetime is checked against the signed relay
event creation time when an Add is created or admitted; delayed processing does
not reinterpret a previously valid Commit using wall-clock time.

Each friend has at most eight local private bundles and eight remote public
packages, with a target of two immediately available packages. Consumption
reports are chunked at 64 references and acknowledged; every chunk is a durable
control event, so a list longer than 64 cannot strand later references.
Exact retirement releases a private reservation. Eight abandoned authenticated
reservations surface a typed terminal convergence error rather than causing
silent starvation, package reuse, or unbounded allocation.
Reported local bundles stay reserved for a delayed winning invitation. A
competing Commit sends retirement after it wins, while successful invitation
adoption consumes the reserved bundle. Expired or excess remote announcements
are explicitly retired instead of accumulating.

An invitation carries the group ID, opaque descriptor and random binding nonce,
descriptor binding, stable topic secret, exact KeyPackage reference, Welcome,
ratchet tree, winning Commit sequence, exact Commit event ID, and Commit
fingerprint. The recipient reads and verifies that retained group event before
installing any cursor or group state. It also requires the authenticated
Welcome GroupInfo confirmation tag to equal that exact public Commit's
confirmation tag, preventing a valid Welcome from a competing Add from being
substituted. The invitation is encrypted and authenticated by the friend
channel. There is no public join operation.

## Group stream

A one-member group and a many-member group are the same primitive. The
descriptor and application bytes are opaque and retained even when the
application does not understand them.

Commits are durable MLS PublicMessages. Application events are durable MLS
PrivateMessages. Murmur currently exposes no expiration or collapse option for
MLS content, avoiding unsafe Secret Tree generation skips.

Inbound application persistence is atomic across:

```text
post-open epoch + opaque event + authenticated sender + replay marker + cursor
```

Inbound Commit persistence is atomic across:

```text
next epoch + membership + replay marker + cursor
```

Removed members keep the relay topic capability but not newer MLS epoch
secrets. Their later injections cannot authenticate as current MLS content and
are quarantined.

Quarantine is bounded to 32 minimal metadata records per topic and never stores
the rejected payload. Group replay fingerprints are bounded to 128 entries;
after eviction, the persisted Secret Tree ratchet still rejects replayed
application ciphertext. Control replay state is retained when pruning could
reapply a semantic control effect.

## Relay envelope

Relay event signatures use strict Ed25519 verification and cover canonical JSON
containing the complete typed topic descriptor, event ID, author, creation time,
optional expiration and collapse key, and opaque payload. Keys and ciphertext
remain `Uint8Array` internally and use unpadded base64url only at JSON and
storage boundaries. Secret capability keys never cross the relay boundary.

For a new event the relay:

1. strictly validates shape and bounds;
2. verifies the Ed25519 signature;
3. enforces the topic's write capability;
4. checks for an existing `(topic, id)` receipt;
5. rejects `createdAt` more than five minutes in the future and requires
   `expiresAt` to remain in the future;
6. atomically allocates a sequence, applies collapse, stores the event, and
   stores its receipt.

There is no maximum past age for `createdAt`. A correctly signed event that the
relay has never accepted remains publishable after offline time or backward
client clock drift; durable outbox work must not become invalid merely because
delivery was delayed. `expiresAt` is the explicit author-selected deadline.

For an existing receipt, steps 1–4 still apply. Equal authenticated content
returns the original sequence even after future-skew or expiration policy would
reject a new event. Different content returns `id_collision`.

## Expiration and collapse

No `expiresAt` means durable. Once expiration passes, the event is omitted from
reads and can be physically deleted.

When `collapseKey` is present, publishing atomically removes all older retained
events in that topic from the same author signing key carrying equal opaque
bytes. Including the author in this identity prevents independent writers to a
public-write `Read Topic` from collapsing one another's state. Clients use
collapse only when the new payload completely replaces the author's earlier
state.

Collapse follows relay arrival order, not an application timestamp or logical
version. A delayed publication carrying older logical state can therefore
arrive later and supersede newer retained state. Applications that use collapse
must carry an authenticated logical version in the opaque payload and reject
regressions when applying events; the relay deliberately does not interpret
that version.

The relay's head sequence never decreases. Expiration and collapse therefore
produce legal sequence holes without reusing sequence numbers.

## Event pages

Events are ordered by sequence and strictly greater than the requested cursor.
`exhausted` is computed from retained candidates before count and encoded-byte
page limits. It is false whenever another retained event follows the page, even
if the returned page is shorter than the requested count.

Stores first fetch at most `limit + 1` retained `(sequence, encoded length)`
metadata candidates under one snapshot. After exact page selection, a second
indexed query in the same transaction hydrates only the selected event JSON
rows. SQLite and Postgres therefore share page-budget semantics without
materializing every maximum-sized candidate. The first retained event is always
selected and hydrated, even when it alone exceeds a caller-supplied page budget.

Clients advance the last returned event to `head` only when `exhausted` is true.
Otherwise they advance to that event's sequence and request the next page.

## Read authentication

Public `Write Topic` reads need no proof. `Read Topic` and `Read and Write Topic`
use a short-lived one-use relay challenge:

```ts
interface ReadChallenge {
    id: string;
    nonce: Uint8Array;
    expiresAt: number;
}
```

The client signs canonical JSON:

```ts
{
    challengeId: string;
    nonce: string;
    topic: RelayTopic;
    since: string;
    limit: number;
    waitMilliseconds: number;
}
```

The relay removes the challenge before signature verification. Consequently a
successful proof, an invalid attempt, or a replay consumes it. The challenge is
also bound to the topic descriptor and expiration. Issuance and atomic
consumption use shared relay storage rather than process memory.

## Stateful client contract

```ts
interface TopicAccess {
    topic: RelayTopic;
    readSecretKey?: Uint8Array;
    writeSecretKey?: Uint8Array;
}
```

For protected writes, the client derives the public key from `writeSecretKey`
and requires it to equal `topic.writeKey` before signing. This permits several
different Murmur identities to share one MLS or control-stream capability
without exposing their identity signing keys to the relay envelope.

For `Read Topic`, no designated write capability exists, so the client's normal
identity signer is a valid relay author.

There is exactly one `RelayTransport` per stateful client. Multi-relay ordering,
failover, and relay-specific cursors are not protocol concepts.

Clients independently validate descriptor shape, event signature, topic
identity, sequence range, and designated write author on received pages. Sync
passes are serialized, and a pending delivery must advance transactionally
before that topic is read again.
