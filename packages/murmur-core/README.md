# `@murmur/core`

Transport-neutral, end-to-end encrypted messaging primitives for browsers and
Node.js. The package provides identities, authenticated profiles, direct
messages, encrypted files, durable relay delivery, and convergent text
documents. Applications own message semantics and provide durable storage.

```text
application
    |
MurmurClient
    |---- MurmurStore
    `---- RelayTransport[]
              |
          dumb relays
```

The package is ESM-only, side-effect free, and includes TypeScript declarations
and source maps. It has no Node.js imports. Node.js 20 or later is supported;
modern browsers can use the same exports.

> `@murmur/core` is a `0.x` API and has not received an independent security
> audit. MLS groups live in the separate experimental `@murmur/mls` package and
> are not part of this package's stable surface.

## Install

```bash
pnpm add @murmur/core
```

## Start a client

```typescript
import {
    HttpRelayTransport,
    MemoryMurmurStore,
    MurmurClient,
    generateIdentityKeyPair,
    identityInboxTopic,
    utf8Decode,
} from "@murmur/core";

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

    // Acknowledgement is explicit. Call it only after application state is
    // durably committed.
    await received.acknowledge();
}
```

`MemoryMurmurStore` is useful for tests and examples. Production applications
should implement `MurmurStore` with IndexedDB, SQLite, or another transactional
store.

## Public API

Everything is available from `@murmur/core`. Domain subpaths are also public for
smaller, explicit imports:

```typescript
import { MurmurClient } from "@murmur/core/client";
import { generateIdentityKeyPair } from "@murmur/core/crypto";
import type { RelayTransport } from "@murmur/core/transport";
```

| Import                   | Main API                                                                                        |
| ------------------------ | ----------------------------------------------------------------------------------------------- |
| `@murmur/core/client`    | `MurmurClient`, `PublishResult`, `ReceivedEvent`, `RetryOutboundReport`                         |
| `@murmur/core/crypto`    | identity generation/import/destruction, signing, verification, sealed boxes, hashing            |
| `@murmur/core/identity`  | public identity serialization, inbox topics, encrypted profiles, `ContactBook`                  |
| `@murmur/core/messaging` | direct-message encryption and acceptance, file encryption, message codecs and limits            |
| `@murmur/core/transport` | `RelayTransport`, `HttpRelayTransport`, signed relay events, queue requests, blobs, wire codecs |
| `@murmur/core/storage`   | `MurmurStore`, `StoreTransaction`, `MemoryMurmurStore`                                          |
| `@murmur/core/document`  | `SharedTextDocument` and convergent insert/delete operations                                    |
| `@murmur/core/utils`     | strict base64url, UTF-8, canonical JSON, byte comparison and zeroing                            |

### `MurmurClient`

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

Publishing succeeds when at least one configured transport accepts the event.
The durable outgoing record retains which transports accepted it, so
`retryOutbound` can resume the remaining publications. Incoming copies from
multiple transports are authenticated and deduplicated. A `ReceivedEvent`
remains pending until its `acknowledge()` method is called.

### Identities and contacts

```typescript
const alice = generateIdentityKeyPair();
const bob = generateIdentityKeyPair();

const encrypted = encryptProfileForContact(alice, bob, {
    name: "Alice",
    metadata: { role: "agent" },
});
const opened = decryptContactProfile(bob, encrypted);

const contacts = new ContactBook(bob, store);
await contacts.save(opened);
```

Internally, all keys are `Uint8Array`. Base64url is used only by serialization
helpers and wire formats. Call `destroyIdentity(identity)` when secret key
material is no longer needed.

### Direct messages and files

```typescript
const attachment = encryptFile(fileBytes, {
    name: "report.pdf",
    mediaType: "application/pdf",
});
await murmur.putBlob(attachment.blob.bytes);

const message = createPrivateMessage("Attached", [attachment.descriptor]);
const envelope = encryptPrivateMessageForContact(alice, bob, message);
const opened = decryptPrivateMessageFromContact(bob, envelope);
```

Use `acceptPrivateMessageFromContact` when receiving durable application data.
It commits the application record and replay marker in one `MurmurStore`
transaction and reports either `"opened"` or `"duplicate"`.

### Replaceable boundaries

Implement `RelayTransport` to use a LAN, WebRTC, Bluetooth, or another relay:

```typescript
interface RelayTransport {
    readonly id: string;
    publish(event: RelayEvent): Promise<void>;
    subscribe(subscription: TopicSubscription): Promise<void>;
    pull(
        request: QueueReadRequest,
        waitMilliseconds?: number,
        signal?: AbortSignal,
    ): Promise<readonly RelayDelivery[]>;
    acknowledge(request: QueueAcknowledgeRequest): Promise<void>;
    putBlob(blob: RelayBlob): Promise<void>;
    getBlob(id: string): Promise<RelayBlob | undefined>;
}
```

Implement `MurmurStore` with atomic transactions:

```typescript
interface MurmurStore {
    get(key: string): Promise<Uint8Array | undefined>;
    set(key: string, value: Uint8Array): Promise<void>;
    delete(key: string): Promise<void>;
    list(prefix: string): Promise<ReadonlyMap<string, Uint8Array>>;
    transaction<Result>(
        operation: (transaction: StoreTransaction) => Promise<Result>,
    ): Promise<Result>;
}
```

## Publish

The `prepack` lifecycle runs tests, strict TypeScript validation, and a clean
declaration build before npm creates the tarball:

```bash
pnpm --filter @murmur/core pack
pnpm --filter @murmur/core publish
```

Publishing requires npm access to the public `@murmur` scope. The package
metadata sets public access and the npm registry explicitly.
