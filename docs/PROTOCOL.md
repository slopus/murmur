# Protocol

This document describes the clean Murmur relay envelope. Higher-level friend
exchange and MLS group payload formats are intentionally specified separately;
the relay treats all payload bytes as opaque.

## Cryptographic conventions

- Keys and ciphertext are `Uint8Array` internally.
- JSON and storage boundaries use canonical unpadded base64url.
- Signatures are Ed25519 with strict RFC 8032 verification (`zip215: false`).
- Hashing is SHA-256.
- Signatures cover recursively key-sorted canonical JSON.
- Secret capability keys never cross the relay boundary.

## Topic descriptors

```ts
type RelayTopic =
    | {
          type: "write";
          name: string;
          writeKey: Uint8Array;
      }
    | {
          type: "read";
          name: string;
          readKey: Uint8Array;
      }
    | {
          type: "read-write";
          name: string;
          readKey: Uint8Array;
          writeKey: Uint8Array;
      };
```

The physical topic ID is:

```text
base64url(SHA-256(canonical JSON(topic descriptor)))
```

The descriptor is included in every signed event, so changing its type, name,
or authorization keys produces both a different signature preimage and a
different physical topic.

`Write Topic` requires the event author key to equal `writeKey`.
`Read Topic` accepts any valid event author. `Read and Write Topic` enforces its
`writeKey`.

## Relay events

```ts
interface SignedRelayEvent {
    version: 1;
    id: string;
    topic: RelayTopic;
    author: {
        signingKey: Uint8Array;
    };
    createdAt: number;
    expiresAt?: number;
    collapseKey?: Uint8Array;
    payload: Uint8Array;
    signature: Uint8Array;
}
```

`id` encodes 32 random bytes. The signature covers every field except
`signature`, after byte arrays are encoded as base64url.

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

The relay's head sequence never decreases. Removed events therefore produce
legal holes:

```text
stored sequences: 1, 2, 3, 4
collapse 2 and expire 3
retained:         1,       4
head:                         4
```

## Event pages

```ts
interface EventPage {
    events: readonly {
        seq: bigint;
        event: SignedRelayEvent;
    }[];
    head: bigint;
    exhausted: boolean;
}
```

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
