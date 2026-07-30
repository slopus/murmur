# `@slopus/murmur`

Transport-neutral, end-to-end encrypted messaging for browsers and Node.js. The
single package provides identities, authenticated profiles, direct messages,
encrypted files, durable relay delivery, MLS groups, and convergent text
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

> `@slopus/murmur` is a `0.x` API and has not received an independent security
> audit. Its MLS implementation is an experimental Murmur profile and remains
> an RFC 9420 subset.

## Install

```bash
pnpm add @slopus/murmur
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

    // Acknowledgement is explicit. Call it only after application state is
    // durably committed.
    await received.acknowledge();
}
```

`MemoryMurmurStore` is useful for tests and examples. Production applications
should implement `MurmurStore` with IndexedDB, SQLite, or another transactional
store.

## Public API

The common API is available from `@slopus/murmur`. Domain subpaths and the MLS
API are part of the same npm package:

```typescript
import { MurmurClient } from "@slopus/murmur/client";
import { generateIdentityKeyPair } from "@slopus/murmur/crypto";
import { MlsGroupChannel } from "@slopus/murmur/mls";
import type { RelayTransport } from "@slopus/murmur/transport";
```

| Import                     | Main API                                                                                        |
| -------------------------- | ----------------------------------------------------------------------------------------------- |
| `@slopus/murmur`           | complete common API                                                                             |
| `@slopus/murmur/client`    | `MurmurClient`, `PublishResult`, `ReceivedEvent`, `RetryOutboundReport`                         |
| `@slopus/murmur/crypto`    | identity generation/import/destruction, signing, verification, sealed boxes, hashing            |
| `@slopus/murmur/identity`  | public identity serialization, inbox topics, encrypted profiles, `ContactBook`                  |
| `@slopus/murmur/messaging` | direct-message encryption and acceptance, file encryption, message codecs and limits            |
| `@slopus/murmur/mls`       | MLS groups, epochs, KeyPackages, Commits, Welcome, TreeKEM, and private messages                |
| `@slopus/murmur/transport` | `RelayTransport`, `HttpRelayTransport`, signed relay events, queue requests, blobs, wire codecs |
| `@slopus/murmur/storage`   | `MurmurStore`, `StoreTransaction`, `MemoryMurmurStore`                                          |
| `@slopus/murmur/document`  | `SharedTextDocument` and convergent insert/delete operations                                    |
| `@slopus/murmur/utils`     | strict base64url, UTF-8, canonical JSON, byte comparison and zeroing                            |

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

The `prepack` lifecycle runs common and MLS tests, strict TypeScript validation,
and a clean declaration build before npm creates the single tarball:

```bash
pnpm --filter @slopus/murmur pack
pnpm --filter @slopus/murmur publish
```

Publishing requires npm access to the public `@slopus` scope. The package
metadata sets public access and the npm registry explicitly.
