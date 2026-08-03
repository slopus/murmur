# Protocol

This document describes the bytes Murmur clients place in relay events. The
relay protocol itself is in [RELAY_API.md](RELAY_API.md). The relay treats all
application payloads, snapshots, and list elements as opaque bytes.

## Conventions and primitives

All byte values use unpadded base64url at JSON and storage boundaries.
Internally, keys and ciphertexts are `Uint8Array`.

| Purpose                                 | Current construction                                    |
| --------------------------------------- | ------------------------------------------------------- |
| Relay-event and application signatures  | Ed25519, strict RFC 8032 verification (`zip215: false`) |
| Identity key agreement                  | X25519                                                  |
| Profile and direct-message sealed boxes | Ephemeral X25519, HKDF-SHA256, AES-256-GCM              |
| File encryption                         | AES-256-GCM                                             |
| Hashing and content addresses           | SHA-256                                                 |
| Local blob-link authentication          | HMAC-SHA256                                             |
| S3 links                                | AWS Signature Version 4                                 |

The sealed-box key is HKDF-SHA256 over the X25519 shared secret. Its salt binds
the ephemeral and recipient public encryption keys, and its information string
is `murmur sealed box v1`. Its AES-GCM nonce is 12 bytes.

Secret arrays are zeroed by the implementation when intermediate work is done
where practical. Zeroing cannot guarantee removal from JavaScript runtimes or
their garbage collectors.

## Relay events

Every topic write is a version-one signed relay event:

```ts
{
    version: 1,
    id: string, // canonical base64url encoding of 32 random bytes
    topic: string,
    author: {
        signingKey: string, // canonical base64url encoding of 32 Ed25519 public-key bytes
    },
    createdAt: number, // integer Unix milliseconds
    payload: string, // base64url opaque bytes
    snapshot?: {
        expectedVersion: number,
        bytes?: string, // absent means delete
    },
    list?: [
        { op: "append", id: string, bytes: string },
        { op: "replace", id: string, expectedVersion?: number, bytes: string },
        { op: "delete", id: string, expectedVersion?: number },
    ],
    signature: string, // canonical base64url encoding of 64 bytes
}
```

`topic` uses `[A-Za-z0-9_.:-]` and is at most 512 characters. List element IDs
use the same alphabet and are at most 256 characters.

The signature authenticates recursively key-sorted canonical JSON containing
every field except `signature`; all byte values have already become base64url
strings. The event ID, topic, author, timestamp, payload, snapshot mutation,
and list mutations are therefore all signed.

For a new event, the relay verifies that signature and enforces a timestamp
within five minutes of its clock. It assigns a gapless sequence local to the
topic only after the event is accepted. A receipt keeps the event's
signature-preimage hash and resulting sequence even after the retained event
body expires, so an exact retry returns its original result before timestamp
validation.

The author signing key is deliberately plaintext: the relay needs it to verify
the event. It is metadata, not an end-to-end identity proof for application
content; application payloads authenticate themselves where that matters.

## Identities and identity inboxes

An identity is:

```text
IdentityKeyPair
├── signingSecretKey / signingKey          Ed25519
└── encryptionSecretKey / encryptionKey    X25519
```

The stable identity ID is the base64url public signing key. Its serializable
public form is:

```ts
{
    signingKey: string,
    encryptionKey: string,
}
```

No account or registry binds these keys to a person. Clients exchange this
public pair out of band. Murmur does not verify that channel.

### First-contact address

```text
identityInboxTopic(identity)
    = "identity:" + base64url(SHA-256(identity.signingKey))
```

This is public by design: anyone who has the recipient's public token can
compute and read it. It is only a first-contact inbox, never a direct-message
topic.

A first-contact client uses `publishUnlinkable()`, which signs the outer relay
event with a fresh one-use identity. The sealed profile payload contains the
actual sender identity. The inbox consequently reveals that a number of
unlinkable contact requests arrived without putting a long-lived sender
identity in the outer event author field.

## Contact profiles

`IdentityProfile` is:

```ts
{
    name: string,
    avatar?: Uint8Array,
    metadata?: Readonly<Record<string, string>>,
}
```

Its JSON encoding is limited to 1 MiB. A profile envelope is:

```ts
{
    version: 1,
    recipient: string, // recipient signing-key identity ID
    ephemeralPublicKey: string,
    nonce: string,
    ciphertext: string,
}
```

Before encryption, the sender creates:

```text
signature = Ed25519.sign(canonical JSON {
    version: 1,
    recipient,
    profile: base64url(profile JSON),
    privateData: base64url(optional bytes),
})

plaintext JSON = {
    sender: { signingKey, encryptionKey },
    profile: base64url(profile JSON),
    privateData: base64url(optional bytes),
    signature: base64url(signature),
}
```

The plaintext is sealed to the recipient X25519 key. The recipient identity and
version are AES-GCM associated data. On receipt, the client checks the envelope
recipient, decrypts it, verifies the sender signature over the recipient-bound
profile, and only then stores the contact. The recipient binding prevents an
observed profile from being replayed to a third identity.

Profiles may carry up to 256 KiB of optional private application bytes. The CLI
uses that channel for a contact's one-use MLS KeyPackage.

## Pairwise addressing

Direct conversations do not use public inboxes. Given self's private X25519
key and the peer's public X25519 key:

```text
sharedSecret = X25519(self.encryptionSecretKey, peer.encryptionKey)
publicKeys   = sort([
    base64url(self.encryptionKey),
    base64url(peer.encryptionKey),
])

pairwiseTopic = "pairwise:" + base64url(SHA-256(canonical JSON {
    context: "murmur/pairwise-topic/x25519-sha256/v1",
    publicKeys,
    sharedSecret: base64url(sharedSecret),
}))
```

The implementation zeros the derived secret and hashing preimage after
derivation. Alice and Bob derive the same topic; possession of both public
identity tokens is insufficient.

This is necessary because topic reads have no authentication. A topic derived
only from a public token would let anyone with that token inspect the event
authors, timing, and sizes of its writer's traffic.

## Direct messages

The decrypted `PrivateMessage` format is:

```ts
{
    version: 1,
    id: string, // base64url encoding of 24 random bytes
    sentAt: number,
    text: string,
    attachments: readonly EncryptedFileDescriptor[],
}
```

The sender first encodes that JSON and signs:

```text
Ed25519.sign(canonical JSON {
    version: 1,
    recipient: recipient identity ID,
    message: base64url(private-message JSON),
})
```

It places the message bytes and signature in JSON, then seals that JSON to the
recipient's **long-term** X25519 key. The final event payload is the UTF-8 JSON
form:

```ts
{
    version: 1,
    sender: { signingKey: string, encryptionKey: string },
    recipient: string,
    ephemeralPublicKey: string,
    nonce: string,
    ciphertext: string,
}
```

The outer sealed-box associated data binds the claimed sender public keys,
recipient identity ID, and version. A receiving client decrypts, checks the
recipient, and verifies the inner sender signature.

The direct-message envelope is both the relay event payload and the bytes of
one appended permanent list element. Its list ID is:

```text
"message:" + base64url(SHA-256(canonical JSON {
    context: "murmur/private-message-list-element/v1",
    sender: base64url(sender signing key),
    id: message ID,
}))
```

That stable author-scoped list ID prevents a retained publication retry from
creating a second message history element.

Text sends managed by `DirectChat` append a second version-one envelope sealed
to the sender's own long-term X25519 key. It is stored on the same pairwise
topic, but never used as the live event payload. Its distinct list ID is:

```text
"self-message:" + base64url(SHA-256(canonical JSON {
    context: "murmur/private-message-self-list-element/v1",
    sender: base64url(sender signing key),
    peer: base64url(recipient signing key),
    id: message ID,
}))
```

The peer binding prevents a retained self copy from being attributed to a
different pairwise conversation. The recipient cannot open this copy. A fresh
sender device can open it, while ignoring the recipient-sealed element. Both
participants collapse their authorized copy to the same logical message ID, so
copies repeated by several relays do not duplicate history. Older topics with
only recipient-sealed elements remain readable by recipients.

The direct-chat outbox remains until every configured relay accepts the logical
send. If a pending signed event approaches the relay's timestamp window, the
client atomically replaces it with a freshly timestamped and signed event whose
topic, payload, and two stable list operations are byte-equivalent. Different
relays may therefore retain different event IDs for one logical message; stable
element IDs and authenticated replay records collapse them.

### Direct-message acceptance

`acceptPrivateMessageFromContact()` uses a local replay key scoped to recipient,
authenticated sender, and a SHA-256 digest of the message ID. In one
`MurmurStore.transaction()` it:

1. decrypts and verifies the message before starting persistence;
2. invokes the application callback only for a new record;
3. records a fingerprint of the complete authenticated message;
4. optionally calls `ReceivedEvent.advanceCursor(transaction)`.

An identical replay returns `"duplicate"` and can advance a pending cursor. A
same-ID message whose authenticated content differs raises
`DirectMessageIdCollisionError` and leaves the transaction unchanged.

Direct messages do **not** have post-compromise security. A stolen long-term
recipient X25519 encryption key can open previously recorded direct-message
sealed boxes and future ones addressed to that key.

`DirectChat` additionally requires the authenticated envelope sender to match
the friend identity that derives the pairwise topic. Invalid envelopes,
same-ID/different-content collisions, and messages received while that friend
is removed are replay-marked and quarantined while the relay cursor advances
atomically. Applications persist their message row in that same transaction,
but own all chat, UI, read-state, and presentation semantics.

## Files and blobs

`encryptFile()` produces:

```ts
{
    descriptor: {
        version: 1,
        blobId: string, // base64url(SHA-256(ciphertext))
        key: Uint8Array, // 32 bytes
        nonce: Uint8Array, // 12 bytes
        name: string,
        mediaType: string,
        plaintextBytes: number,
    },
    blob: {
        id: string,
        bytes: Uint8Array, // AES-GCM ciphertext
    },
}
```

The file key and nonce are random. AES-GCM associated data is canonical JSON of
the descriptor's version, name, media type, and plaintext length. Thus a
modified descriptor does not decrypt. `decryptFile()` verifies the blob content
address, descriptor ID, ciphertext size, AEAD tag, and resulting plaintext
length.

The descriptor is delivered only inside an encrypted direct or MLS message.
Blob transport is separate:

```text
POST /v1/blobs/:id/upload-link
    -> { url, method: "PUT", expiresAt, headers? }

POST /v1/blobs/:id/download-link
    -> { url, method: "GET", expiresAt, headers? }
```

The local backend's `url` is relative to the relay and contains signed expiry
parameters. S3's is an absolute presigned URL. An ordinary unsigned
`PUT /v1/blobs/:id` or `GET /v1/blobs/:id` is not a blob API.

## MLS groups

Murmur implements a tested subset of RFC 9420. A group has a random opaque
`groupId`; each epoch has TreeKEM ratchet state and group membership. Its stable
relay address is:

```text
mlsGroupTopic(groupId) = "mls:" + base64url(SHA-256(groupId))
```

Every epoch uses that one topic. The relay observes only signed outer events
and opaque MLS payloads; it does not interpret group membership or document
traffic.

`MlsGroupChannel` routes a relay event to one current epoch. It distinguishes
MLS PublicMessage-form Commit bytes from application ciphertext, hashes the
payload as a replay fingerprint, and returns one of these delivery outcomes:

| Status                            | Required durable action                                                                                                  |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `opened`                          | Persist application record, post-open epoch checkpoint, replay fingerprint, and cursor together; then `markPersisted()`. |
| `commit`                          | Persist the staged next-epoch checkpoint and Commit marker, `markPersisted()`, then `adopt()`.                           |
| `application-applied` / `applied` | Persist only the relevant cursor if the replay marker is already durable.                                                |
| `removed`                         | Persist group retirement and cursor before `markPersisted()` destroys live state.                                        |
| `deferred`                        | Do not advance automatically. It may be a valid future-epoch message.                                                    |

### Prepare → persist → publish

Sending ratchets secret state. `prepareSend()` returns application ciphertext
and a serialized post-ratchet epoch checkpoint. `prepareCommit()` returns a
Commit, optional Welcome, staged next epoch, and replay fingerprint. In both
cases the caller must:

```text
prepare
    -> atomically persist exact payload, checkpoint, and application outbox
    -> markPersisted()
    -> publish()
    -> for a Commit, adopt()
```

A timeout after publish starts is ambiguous, not a safe failure. The prepared
operation remains staged until a retained Murmur outbound retry confirms the
matching payload.

The order prevents loss of the sender's next state. In particular, publishing a
Commit before the next-epoch private state is durable can permanently lock the
sender out of its own group after a crash.

Groups offer forward-secret epochs after membership transitions. This is better
than direct messages, but it does not repair an unverified identity-token
exchange or make the relay available.

## Shared text documents

A shared document is an operation-based replicated growable array. Its
operations are UTF-8 JSON carried as MLS application data:

```ts
// insert
{
    version: 1,
    type: "insert",
    id: { actor: string, sequence: number },
    after: { actor: string, sequence: number } | null,
    text: string,
}

// delete
{
    version: 1,
    type: "delete",
    id: { actor: string, sequence: number },
    target: { actor: string, sequence: number },
}
```

`actor` is a canonical base64url 32-byte public signing key and `sequence` is a
non-negative 32-bit integer. `SharedTextDocument.apply()` receives both an
operation and the actor authenticated by the MLS leaf; it rejects an operation
whose `id.actor` differs from that actor.

Operations are idempotent and commutative. Concurrent inserts after the same
anchor sort by operation ID. Deletes are permanent tombstones and may arrive
before their target. Replicas retain at most 10,000 operations and 4 MiB of
encoded operation state; when a bound is exceeded, deterministic trimming keeps
the same lowest operation IDs on each replica.
