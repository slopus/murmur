# Protocol

How identities, contacts, messages, groups, and documents work. For the relay's
HTTP surface see [RELAY_API.md](RELAY_API.md); for the security model see
[SECURITY.md](SECURITY.md).

## Primitives

| Purpose                   | Algorithm                                            |
| ------------------------- | ---------------------------------------------------- |
| Signatures                | Ed25519                                              |
| Key agreement             | X25519                                               |
| Direct/profile encryption | ChaCha20-Poly1305 (sealed box, ephemeral sender key) |
| File encryption           | AES-256-GCM                                          |
| Hashing                   | SHA-256                                              |

All key material is `Uint8Array` in memory. Base64url appears only at wire and
storage boundaries. Secrets are zeroed with `zeroBytes` when no longer needed.

## Identity

An identity is **two independent key pairs**:

```text
IdentityKeyPair
├── signing key      Ed25519    authorship  → identityId, inbox topic
└── encryption key   X25519     secrecy     → sealed boxes
```

```typescript
const identity = generateIdentityKeyPair();

identityId(identity); // base64url of the public signing key
identityInboxTopic(identity); // "identity:" + base64url(SHA-256(signing key))
```

Separating the two means a compromise of one capability does not imply the
other, and lets the signing key act as a stable public name while the encryption
key does key agreement.

There is no account, no username, and no registry. An identity is valid the
moment it is generated. Its **token** is the two public keys joined by a dot:

```text
<base64url signing key>.<base64url encryption key>
```

43 characters each. The token carries no secrets and is what you exchange out of
band — QR code, chat, config file, environment variable.

The inbox topic is a hash of the signing key rather than the key itself, so the
relay can route without holding a directory of public keys in the clear.

## Contacts

Adding a contact is one message: a signed profile, sealed to the recipient's
X25519 key, published to the recipient's inbox topic.

```text
1. Out of band:  Alice and Bob exchange identity tokens
2. Alice → Bob:  sign(profile) → seal to Bob's X25519 key → Bob's inbox topic
3. Bob:          open, verify Alice's signature, save to ContactBook
4. Bob → Alice:  the same, in reverse
```

The exchange is two-directional because receiving a profile authenticates the
_sender_ to the recipient, not the other way round. Each side publishes once.

```typescript
const sealed = encryptProfileForContact(alice, bobPublicKeys, {
    name: "Alice",
    metadata: { role: "agent" },
});

const opened = decryptContactProfile(bob, sealed); // throws on a bad signature
await new ContactBook(bob, store).save(opened);
```

Two bindings matter:

- The signature covers the profile **and the recipient identifier**, so a
  profile captured in transit cannot be replayed at a third party.
- The AEAD associated data covers the sender's public keys and the recipient, so
  the envelope cannot be re-attributed to a different sender.

A profile carries a name, an optional avatar, and arbitrary metadata, bounded at
1 MiB before encryption.

The CLI attaches a one-use MLS KeyPackage to the same envelope. That is what
makes a later group invite possible without another round trip.

## Direct messages

```text
message ──► sign(Ed25519, bound to recipient) ──► seal(X25519 + ChaCha20-Poly1305)
                                                            │
                                        relay sees: topic, recipient, size, time
                                                            │
        open ──► verify signature ──► accept exactly once ──► app state ──► ack
```

```typescript
const message = createPrivateMessage("deploy finished");
const envelope = encryptPrivateMessageForContact(alice, bobPublicKeys, message);
await murmur.publish(topic, encodeEncryptedPrivateMessage(envelope), [bobPublicKeys]);
```

Each message gets a fresh ephemeral X25519 key pair, so the sender's long-term
encryption key is never used directly as a DH input for a message.

### Exactly-once acceptance

```typescript
const accepted = await acceptPrivateMessageFromContact(
    store,
    bob,
    envelope,
    async (transaction, opened) => {
        await transaction.set(`chat/${opened.message.id}`, encodeRecord(opened));
    },
);
accepted.status; // "opened" | "duplicate"
```

The persistence callback runs **inside the same store transaction** as the
replay marker, keyed by recipient, sender, and message ID:

- First sight → callback runs, marker written, status `"opened"`.
- Re-delivery of identical content → status `"duplicate"`, safe to acknowledge.
- Same ID with _different_ signed content → `DirectMessageIdCollisionError`.
  The delivery stays unacknowledged for deliberate operator handling rather than
  being silently dropped.

Acknowledge the relay delivery only after this resolves.

### Limits

- 1 MiB maximum relay event payload
- 64 attachments per message
- 64 MiB of aggregate plaintext attachment data per message

## Encrypted files

Files never reach a relay in plaintext.

```text
bytes ──► encryptFile ──► descriptor { key, nonce, name, mediaType, size, blobId }
                       └► blob       { id = SHA-256(ciphertext), ciphertext }
                                             │
        descriptor travels inside the encrypted message; blob goes to the relay
```

```typescript
const attachment = encryptFile(fileBytes, { name: "report.pdf", mediaType: "application/pdf" });
await murmur.putBlob(attachment.blob.bytes);

const message = createPrivateMessage("Attached", [attachment.descriptor]);
```

The file's name, media type, and plaintext length are bound as AEAD associated
data, so metadata cannot be altered without breaking decryption. Blob IDs are
content hashes, which makes storage self-verifying and deduplicating.
`decryptFile` re-checks the hash, the descriptor match, and the plaintext length
before returning bytes. Possession of a blob without its descriptor is useless.

## MLS groups

Groups use an RFC 9420 subset: a TreeKEM ratchet tree with forward-secret
epochs. Every membership change is a Commit that advances the epoch.

```text
Epoch 1: {Alice}
   │ Commit(add Bob) ─────► Welcome to Bob
Epoch 2: {Alice, Bob}
   │ Commit(add Carol) ───► Welcome to Carol
Epoch 3: {Alice, Bob, Carol}
   │ Commit(remove Bob)
Epoch 4: {Alice, Carol}        Bob cannot read anything from here on
```

All epochs of a group share one opaque topic:

```text
mlsGroupTopic(groupId) = "mls:" + base64url(SHA-256(groupId))
```

### prepare → persist → publish

Every outbound group operation follows the same three steps, and the ordering is
mandatory:

```typescript
const prepared = channel.prepareSend(utf8Encode("hello team"));

await store.transaction(async (transaction) => {
    await transaction.set(stateKey, prepared.serializeEpoch());
    await transaction.set(outboxKey, prepared.payload);
});

prepared.markPersisted();
await prepared.publish(murmur);
```

Sealing a message ratchets the epoch. If the ciphertext were published before
the post-ratchet state was durably written, a crash in between would leave the
sender unable to reproduce its own key schedule. For Commits the consequence is
worse: publishing a Commit whose next-epoch private state was lost locks the
member out of their own group permanently. `prepareCommit` therefore stages the
next epoch and only `adopt()`s it after the checkpoint is durable.

A publication whose outcome is unknown — a network timeout — stays _staged_
until the retained outbox resolves it via `confirmPublished()`.

### Receiving

`channel.handle(received)` returns one of:

| Status                            | Meaning                                                                                         |
| --------------------------------- | ----------------------------------------------------------------------------------------------- |
| `opened`                          | Application message decrypted. Persist the epoch checkpoint with your record, then acknowledge. |
| `commit`                          | Authenticated Commit staged. Persist the next epoch, then `adopt()`.                            |
| `applied` / `application-applied` | Replay already reflected in durable state. Safe to acknowledge.                                 |
| `removed`                         | A Commit removed you. Persist retirement, then secrets are destroyed.                           |
| `deferred`                        | Not openable yet — possibly a future epoch. **Not** auto-acknowledged.                          |
| `undefined`                       | Another channel owns this topic.                                                                |

Membership is enforced by cryptography, not by the relay. A relay that drops,
reorders, or duplicates group traffic cannot forge membership; it can only
degrade availability.

## Shared documents

A shared document is an operation-based replicated text object carried inside
ordinary MLS application messages. There is no relay-side merge and no relay
code that knows a document exists.

```typescript
const document = new SharedTextDocument();
const insert = createDocumentInsert(createDocumentOperationId(actorId, 1), null, "hello");

document.apply(insert, actorId); // actorId must be the authenticated MLS leaf
document.render(); // "hello"
document.operations(); // stable log for persistence or catch-up
```

Operations are inserts anchored after another operation (or at the start) and
deletes that tombstone a target.

- **Idempotent and commutative**, so any delivery order, arbitrary re-delivery,
  and long offline periods converge.
- **Tombstones may precede their target**, which is required when deletes and
  inserts race.
- **Concurrent inserts at the same anchor** are ordered by canonical operation
  ID, identically on every replica.
- **Actor binding**: `apply` rejects an operation whose ID actor differs from
  the authenticated MLS leaf, so a member cannot forge an edit attributed to
  another member.
- **Bounded**: 10 000 operations and 4 MiB of retained state per document, with
  deterministic trimming so replicas that hit the bound still agree.
