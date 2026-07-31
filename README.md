# Murmur

End-to-end encrypted messaging over deliberately dumb relays.

Murmur ships as one public library, [`@slopus/murmur`](packages/murmur-core),
for browsers and Node.js. It provides identities, contact profiles, private
messages, encrypted files, durable delivery, MLS groups, and convergent shared
text documents. Applications decide what messages mean and supply their own
durable storage.

```text
application
    |
@slopus/murmur
    |---- MurmurStore
    `---- RelayTransport[]
              |
          dumb relays
```

> Murmur is a `0.x` project. Its cryptographic implementation has not received
> an independent security audit, and its MLS support is a tested Murmur profile
> rather than a complete general-purpose implementation of RFC 9420.

## Install

```bash
pnpm add @slopus/murmur
```

The package is ESM-only, side-effect free, and includes TypeScript declarations
and source maps. It has no Node.js imports and supports Node.js 20 or later and
modern browsers.

## Quick start

```typescript
import {
    HttpRelayTransport,
    MemoryMurmurStore,
    MurmurClient,
    generateIdentityKeyPair,
    identityInboxTopic,
    utf8Decode,
} from "@slopus/murmur";

const identity = generateIdentityKeyPair();
const store = new MemoryMurmurStore();
const relay = new HttpRelayTransport("primary", "https://relay.example");
const murmur = new MurmurClient({
    identity,
    store,
    transports: [relay],
});

await murmur.subscribe(identityInboxTopic(identity));

for await (const received of murmur.events()) {
    console.log(utf8Decode(received.event.payload));

    // Acknowledge only after application state is durably committed.
    await received.acknowledge();
}
```

`MemoryMurmurStore` is intended for examples and tests. Production applications
should implement `MurmurStore` with IndexedDB, SQLite, or another transactional
store.

## What the library provides

- Independent Ed25519 signing and X25519 encryption identity keys.
- Authenticated, encrypted contact profiles addressed by public key.
- Replaceable relay transports with multi-relay publication and deduplication.
- Explicit acknowledgements and retained outgoing events for offline delivery.
- Signed and encrypted direct messages with durable replay protection.
- Content-addressed encrypted files with authenticated metadata.
- MLS groups with KeyPackages, Welcome, Commit, TreeKEM, and forward-secret
  epoch state.
- Operation-based shared text documents that converge across group members.

All secret keys are `Uint8Array` values internally. Base64url exists only at
serialization and wire boundaries.

## Public API

Everything below belongs to the same `@slopus/murmur` npm package:

| Import                     | Main API                                                                              |
| -------------------------- | ------------------------------------------------------------------------------------- |
| `@slopus/murmur`           | complete common API                                                                   |
| `@slopus/murmur/client`    | `MurmurClient`, delivery, acknowledgement, retry, and blob operations                 |
| `@slopus/murmur/crypto`    | identity keys, signing, verification, sealed boxes, hashing, and secret destruction   |
| `@slopus/murmur/identity`  | identity serialization, inbox topics, encrypted profiles, and `ContactBook`           |
| `@slopus/murmur/messaging` | direct messages, durable replay acceptance, encrypted files, codecs, and limits       |
| `@slopus/murmur/mls`       | groups, epochs, KeyPackages, Commits, Welcome, TreeKEM, and private messages          |
| `@slopus/murmur/transport` | `RelayTransport`, `HttpRelayTransport`, signed events, queues, blobs, and wire codecs |
| `@slopus/murmur/storage`   | `MurmurStore`, `StoreTransaction`, and `MemoryMurmurStore`                            |
| `@slopus/murmur/document`  | `SharedTextDocument` and convergent insert/delete operations                          |
| `@slopus/murmur/utils`     | strict base64url, UTF-8, canonical JSON, byte comparison, copying, and zeroing        |

The main client surface is:

```typescript
new MurmurClient({
    identity: IdentityKeyPair,
    store: MurmurStore,
    transports: readonly RelayTransport[],
    outboundHistoryLimit?: number,
});

client.subscribe(topic): Promise<void>;
client.publish(topic, payload, recipients?): Promise<PublishResult>;
client.publishEvent(event): Promise<PublishResult>;
client.retryOutbound(): Promise<readonly PublishResult[]>;
client.retryOutboundSettled(): Promise<RetryOutboundReport>;
client.sync(waitMilliseconds?, signal?): Promise<readonly ReceivedEvent[]>;
client.events(signal?, waitMilliseconds?): AsyncIterable<ReceivedEvent>;
client.putBlob(ciphertext): Promise<RelayBlob>;
client.getBlob(id): Promise<RelayBlob | undefined>;
```

See the [library API guide](packages/murmur-core/README.md) for identity,
messaging, storage, and transport examples. The MLS implementation and its
supported RFC subset are described in
[MLS internals](packages/murmur-mls/README.md).

## Delivery model

Publishing succeeds after at least one configured transport accepts an event.
Murmur remembers which transports accepted it so later retries can resume the
remaining publications.

Incoming copies from multiple relays are authenticated, merged, ordered, and
deduplicated. Delivery to application code is acknowledged by hand. An
application should commit its own state first, then call
`received.acknowledge()`. Unacknowledged events are delivered again after a
restart.

The relay cannot decrypt profiles, messages, files, group traffic, or shared
documents. It does observe routing identifiers, timing, and ciphertext sizes.

## CLI

The `murmur-chat` package exposes the same system to people and agents from a
Node.js command line:

```bash
pnpm add --global murmur-chat

murmur --relay http://127.0.0.1:8787 sign-in --first-name Alice
murmur me
murmur contacts add <identity-token>
murmur send --to <identity-id> --message "hello"
murmur sync
```

The CLI also supports encrypted attachments, MLS group creation and membership,
group messages, and shared documents. See the
[CLI guide](packages/murmur-cli/README.md).

## Run a local relay

The default Node relay uses SQLite and exposes the browser-safe HTTP transport:

```bash
pnpm --filter @murmur/relay-node build
PORT=8787 node packages/murmur-relay-node/dist/server/main.js
```

Relay state defaults to `./data/murmur-relay.sqlite`. Set
`MURMUR_RELAY_DB`, `MURMUR_RELAY_ORIGINS`, `HOST`, or `PORT` to override the
defaults.

The relay only authenticates envelopes, fans events out to subscribers or
explicit recipients, retains delivery queues until acknowledgement, and stores
content-addressed ciphertext blobs.

## Repository

```text
master-plans/                user-directed product intent
packages/
  murmur-core/               the public @slopus/murmur package
  murmur-mls/                private MLS implementation bundled into the library
  murmur-relay/              runtime-neutral dumb relay
  murmur-relay-node/         SQLite and HTTP relay host
  murmur-cli/                Node.js CLI
  murmur-server/             historical pre-relay server retained during migration
```

The [product vision](master-plans/01-vision.md) and
[code organization rules](master-plans/02-code-organization.md) are the source
of truth. Historical code and documents do not override them.

## Development

This is a pnpm workspace. Node.js 22.5 or later is required for the full
workspace because the CLI and Node relay use `node:sqlite`.

```bash
pnpm install
pnpm test
pnpm typecheck
pnpm build
pnpm lint
pnpm format:check
```

Before committing:

```bash
pnpm format
```

To inspect the exact npm artifact:

```bash
pnpm --filter @slopus/murmur pack
```

## License

[MIT](packages/murmur-core/LICENSE)
