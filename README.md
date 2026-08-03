# Murmur

End-to-end encrypted messaging and shared state over deliberately dumb,
Node-hosted relays.

Murmur ships one public, browser-safe ESM library,
[`@slopus/murmur`](packages/murmur-core), plus the `murmur-chat` CLI. The
library supplies identities, encrypted contacts and direct messages, encrypted
files, durable topic synchronization, MLS groups, and convergent shared text.
Applications choose the meaning of their data and own their durable local
storage.

```text
application
    |
@slopus/murmur ─── MurmurStore       application-owned, transactional state
    |
HttpRelayTransport ─── Murmur relay  signed opaque topic state
```

> Murmur is a `0.x` project. It has not received an independent security
> audit. Its MLS implementation is a tested Murmur profile and RFC 9420 subset,
> not a complete general-purpose MLS implementation.

## What it is for

| Use case                     | What Murmur provides                                                                              |
| ---------------------------- | ------------------------------------------------------------------------------------------------- |
| Agent or human direct chat   | Encrypted messages on a pairwise capability topic, with a permanent message list for new devices. |
| Offline-capable applications | A snapshot and ordered list for catch-up, plus a bounded event log for incremental sync.          |
| Encrypted file handoff       | Client-side AES-GCM encryption and content-addressed ciphertext blobs.                            |
| Group chat                   | MLS epochs over a TreeKEM ratchet tree; membership changes are cryptographic Commits.             |
| Shared text                  | Operation-based replicated text carried as ordinary MLS application messages.                     |
| Self-hosting                 | A Node relay backed by SQLite for one instance or Postgres for multiple instances.                |

The relay is deliberately not a messaging application. It stores and routes
opaque topic state, verifies relay-event signatures, applies limits, and
provides blob-transfer links. It does not know whether a topic contains a chat,
profile, MLS group, document, or something else.

## Topic model

Every topic has three independent parts:

```text
signed event
    |
    v
+---------------- opaque topic ----------------+
| snapshot?       ordered list       event log |
| current bytes   current elements   bounded    |
+------------------------------------------------+
    permanent*       permanent*      7 days by default

* The entire topic is dropped after 30 days without a successful publish.
```

The snapshot and ordered list are current durable state. The list is the chat
history for direct messages, so a new device reads state and every list page; it
does not depend on replaying old events. The event log is only incremental
change history and expires after its retention window.

One signed event may atomically replace or delete the snapshot and append,
replace, or delete up to 256 list elements. Snapshot and list versions support
optimistic concurrency. A snapshot mutation with `expectedVersion: 0` means
"expect no current snapshot." A conflicting mutation returns HTTP 409 with the
current versions.

Blob lifetime is independent of topic retention. The built-in local backend
keeps installed blobs until its storage is managed separately; the S3 backend
delegates lifecycle to the bucket.

## Identities

An identity has two independent long-term key pairs:

```text
IdentityKeyPair
├── Ed25519 signing key       identifies relay-event and application authors
└── X25519 encryption key     receives sealed profiles and direct messages
```

There is no account, username, or relay-side identity registry. Public identity
tokens are exchanged out of band. The library's public representation is:

```ts
import { generateIdentityKeyPair, serializePublicIdentity } from "@slopus/murmur";

const alice = generateIdentityKeyPair();
const alicePublicIdentity = serializePublicIdentity(alice);
// { signingKey: "...", encryptionKey: "..." }
```

The two keys in a token are not authenticated by any outside system. Verify the
out-of-band channel yourself: there is no safety-number comparison or
key-transparency service. A machine-in-the-middle during token exchange defeats
the protections that follow.

## Adding contacts

First contact intentionally uses a publicly derivable inbox topic:

```mermaid
sequenceDiagram
    participant A as Alice
    participant R as Relay
    participant B as Bob

    Note over A,B: Exchange public identity tokens out of band
    A->>R: one-use relay author + sealed, signed profile to Bob's inbox
    B->>R: read events from Bob's inbox
    B->>B: open box, verify Alice's signature, save contact
    B->>R: mirror the same action to Alice's inbox
```

`identityInboxTopic(publicKey)` is derived from the recipient's public signing
key. Anyone who knows an identity token can compute and read that inbox, so it
is for first contact only. The sender's profile is sealed to the recipient and
the client publishes it with `publishUnlinkable()`, which creates a one-use
relay signing identity. An observer can learn that _N unlinkable contact
requests_ arrived, but not which identities sent them.

This avoids a subtle privacy failure. Every relay event contains
`author.signingKey` in plaintext so the relay can verify its signature. If
ongoing traffic used a topic derived from a public identity key, anybody holding
that identity token could learn who wrote to that identity and when.

```ts
import {
    deserializePublicIdentity,
    encryptProfileForContact,
    identityInboxTopic,
    utf8Encode,
} from "@slopus/murmur";

// bobToken is the serialized public identity received out of band.
const bob = deserializePublicIdentity(bobToken);
const profile = encryptProfileForContact(alice, bob, { name: "Alice" });
const bytes = utf8Encode(JSON.stringify(profile));

await client.publishUnlinkable(identityInboxTopic(bob), bytes);
```

Receiving and opening a profile authenticates the sender to the recipient; it
does not authenticate the recipient to the sender. Contact exchange is
therefore two-directional.

## Private messaging

Ongoing direct traffic uses a different topic:

```text
Alice's X25519 secret ─┐
                       ├── X25519 shared secret ──► pairwise capability topic
Bob's X25519 public  ──┘
```

`pairwiseTopic(self, peer)` hashes X25519 shared-secret material together with
a fixed domain string and both canonically ordered public encryption keys. Only
the two parties can compute it from their keys. Reads are otherwise
unauthenticated: knowing a topic ID is the capability to read it.

A direct message is signed by its sender, then sealed to the recipient's
long-term X25519 key using an ephemeral X25519 sender key. The same encrypted
envelope is published as the event payload and appended to the permanent list:

```ts
import {
    createPrivateMessage,
    encodeEncryptedPrivateMessage,
    encryptPrivateMessageForContact,
    pairwiseTopic,
    privateMessageListElementId,
} from "@slopus/murmur";

const message = createPrivateMessage("deploy finished");
const envelope = encryptPrivateMessageForContact(alice, bob, message);
const bytes = encodeEncryptedPrivateMessage(envelope);
const topic = pairwiseTopic(alice, bob);

await client.publish(topic, bytes, {
    list: [
        {
            op: "append",
            id: privateMessageListElementId(alice, message),
            bytes,
        },
    ],
});
```

The relay does not decide when application work is durable. `sync()` reads one
retained event page for each subscribed topic and relay; repeat it to drain
later pages, or use `client.events()`. A received event advances its cursor
only inside the application's `MurmurStore` transaction:

```ts
const result = await client.sync();
if (result.status === "events") {
    for (const received of result.events) {
        await store.transaction(async (transaction) => {
            // Authenticate/interpret application data, then write its durable consequence.
            await transaction.set(`events/${received.event.id}`, received.event.payload);
            await received.advanceCursor(transaction);
        });
    }
}
```

If the transaction fails or the process crashes first, the cursor remains
unchanged and the event is delivered again. There is no `acknowledge()` API and
no relay recipient queue.

For direct messages, `acceptPrivateMessageFromContact()` combines message
authentication, a sender/message-ID replay marker, the application callback,
and the cursor advance in one transaction. It reports `"opened"` for a first
message and `"duplicate"` for an identical replay; a same-ID message with
different authenticated content throws.

## Cursors and resets

Each cursor belongs to one relay and one topic. A normal cursor only moves one
sequence forward at a time. A relay returns `reset: true` if that cursor is
older than retained history or ahead of the topic head.

`MurmurClient.sync()` makes reset handling explicit:

```ts
const result = await client.sync();
if (result.status === "reset") {
    for (const reset of result.resets) {
        await client.loadTopic(
            reset.topic,
            async (transaction, state) => {
                // Replace local materialized state using state.snapshot and state.elements.
                // This callback and the cursor installation are one transaction.
                await transaction.set(`topic/${state.topic}/loaded`, new Uint8Array());
            },
            reset.relayId,
        );
    }
} else {
    // Process result.events and call advanceCursor(transaction).
}
```

`loadTopic()` reads the snapshot, follows the list to `nextCursor: null`, runs
the callback, and installs the loaded head sequence atomically. A reset cannot
be mistaken for "caught up."

## Files

Files are encrypted before upload. The encrypted message carries an
`EncryptedFileDescriptor` containing the random AES-GCM key, nonce, name,
media type, plaintext size, and ciphertext blob ID. The relay stores only the
ciphertext addressed by `SHA-256(ciphertext)`.

```text
plaintext ──► AES-256-GCM ──► ciphertext blob ──► relay/S3
                  |
                  └── descriptor ──► encrypted message or MLS application data
```

`MurmurClient.putBlob()` asks a relay for an upload link, then transfers the
ciphertext to that link. `getBlob()` requests a download link, validates the
content address, and returns a blob when one relay has it.

```ts
import { decryptFile, encryptFile } from "@slopus/murmur";

const encrypted = encryptFile(fileBytes, {
    name: "report.pdf",
    mediaType: "application/pdf",
});
await client.putBlob(encrypted.blob.bytes);

// Send encrypted.descriptor inside an encrypted message.
const blob = await client.getBlob(encrypted.descriptor.blobId);
if (blob !== undefined) {
    const plaintext = decryptFile(encrypted.descriptor, blob);
}
```

The local relay backend returns a **relative** transfer URL; S3 returns an
absolute presigned URL. `HttpRelayTransport` handles both. Clients implementing
their own transport must do the same.

## Groups and documents

Groups use an MLS RFC 9420 subset: forward-secret epochs over a TreeKEM ratchet
tree. All epochs share one opaque topic derived from a random `groupId`.

```text
Epoch 1 ── Commit(add) ──► Epoch 2 ── Commit(remove) ──► Epoch 3
   {A}                     {A, B}                         {A}
```

Outbound group work must always be:

```text
prepare ──► persist exact ciphertext + next state ──► publish ──► adopt
```

This order is mandatory for application messages and especially Commits. A
published Commit whose next-epoch private state was not durably persisted can
permanently lock its own sender out of the group.

For an already configured `MlsGroupChannel`, its API enforces the order:

```ts
const prepared = channel.prepareSend(applicationBytes);
await store.transaction(async (transaction) => {
    await transaction.set(groupStateKey, prepared.serializeEpoch());
    await transaction.set(groupOutboxKey, prepared.payload);
});
prepared.markPersisted();
await prepared.publish(client);
```

Shared documents are operation-based replicated text carried as ordinary MLS
application messages. Inserts and deletes are idempotent and commutative;
deletes are tombstones that may arrive before their target. The operation actor
must match the MLS-authenticated leaf, so a member cannot attribute an edit to
another member.

## Install and quick start

The public library is ESM-only, has no Node imports or side effects, and
depends only on Noble cryptography:

```bash
pnpm add @slopus/murmur
```

```ts
import {
    HttpRelayTransport,
    MemoryMurmurStore,
    MurmurClient,
    generateIdentityKeyPair,
    identityInboxTopic,
} from "@slopus/murmur";

const identity = generateIdentityKeyPair();
const store = new MemoryMurmurStore();
const client = new MurmurClient({
    identity,
    store,
    transports: [new HttpRelayTransport("primary", "https://relay.example")],
});

await client.subscribe(identityInboxTopic(identity));
```

`MemoryMurmurStore` is for examples and tests. A real application must provide
a durable `MurmurStore` whose `transaction()` method is genuinely atomic.

## CLI

`murmur-chat` exposes the same features through the `murmur` command. It
requires Node 22.5 or later. Results are JSON except for `help`.

```bash
pnpm add --global murmur-chat

murmur sign-in --first-name Alice --relay http://127.0.0.1:8787
murmur me
murmur contacts add <identity-token>
murmur send --to <identity-id-or-token> --message "hello"
murmur sync --realtime --timeout 25000
murmur messages --with <identity-id-or-token>
```

The complete command surface is:

```text
murmur sign-in --first-name <name> [--last-name <name>]
murmur me
murmur contacts [add <identity-token> | remove <identity-id-or-token>]
murmur send --to <identity-id-or-token> --message <text> [--attach <path> ...]
murmur sync [--realtime] [--timeout <milliseconds>]
murmur messages [--with <identity-id-or-token>] [--limit <count>]
murmur attachment --message <id> --name <file> --out <path>
murmur groups
murmur groups create --name <name>
murmur groups invite --group <id-or-name> --contact <identity>
murmur groups remove --group <id-or-name> --contact <identity>
murmur groups send --group <id-or-name> --message <text>
murmur groups messages [--group <id-or-name>] [--limit <count>]
murmur documents [--group <id-or-name>]
murmur documents create --group <id-or-name> --name <name>
murmur documents insert --document <id-or-name> --text <text> [--after <actor>:<sequence>]
murmur documents delete --document <id-or-name> --target <actor>:<sequence>
```

Global relay selection is repeatable `--relay <url>` or the comma-separated
`MURMUR_RELAYS` environment variable. Local state is `~/.murmur/murmur.sqlite`
by default; use `--db <sqlite-path>` or `MURMUR_HOME` to choose another
location.

## Run a relay

For local source development, build and start the `@murmur/relay` package with
Node:

```bash
pnpm --filter @murmur/relay build

MURMUR_RELAY_STORE=sqlite \
MURMUR_RELAY_DB=./data/murmur-relay.sqlite \
pnpm --filter @murmur/relay start
```

SQLite is the default. Postgres enables a shared store and cross-instance
long-poll wakeups:

```bash
MURMUR_RELAY_STORE=postgres \
MURMUR_RELAY_DB=postgresql://user:password@host/murmur \
pnpm --filter @murmur/relay start
```

See [Deployment](docs/DEPLOYMENT.md) for all environment variables, blob
backends, the standalone Bun executable, Docker and
[k3s](murmur-relay.k3s.yaml), proxy configuration, and production caveats.

## Repository

```text
master-plans/                user-directed product intent
docs/                        architecture, protocol, API, deployment, security
packages/
  murmur-core/               published @slopus/murmur library
  murmur-mls/                MLS implementation bundled into the library build
  murmur-relay/              Node relay: HTTP host, SQLite, Postgres, blobs
  murmur-cli/                published murmur-chat Node CLI
```

- [Architecture](docs/ARCHITECTURE.md) — layers, trust boundary, state and cursor flows
- [Protocol](docs/PROTOCOL.md) — identities, contacts, messages, files, MLS, documents
- [Relay API](docs/RELAY_API.md) — exact HTTP surface, limits, and extension interfaces
- [Deployment](docs/DEPLOYMENT.md) — local, single-instance, and Postgres deployment
- [Security](docs/SECURITY.md) — guarantees, threat model, and current gaps

## Development

This is a pnpm workspace. Node 22.5 or later is required for the full workspace
because the relay and CLI use `node:sqlite`.

```bash
pnpm test
pnpm typecheck
pnpm build
pnpm lint
pnpm format:check
```

## License

[MIT](packages/murmur-core/LICENSE)
