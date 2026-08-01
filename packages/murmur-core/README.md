# `@slopus/murmur`

Browser-safe end-to-end encrypted messaging over deliberately dumb relays. The
single ESM package provides identities, contact profiles, pairwise messages,
encrypted files, durable topic synchronization, MLS groups, and convergent text
documents. Applications own semantics and durable storage.

```text
application
    |
MurmurClient ---- MurmurStore
    |
RelayTransport[] ---- topic snapshot + permanent list + bounded event log
```

The package has no Node imports or side effects and depends only on Noble
cryptography. It is a `0.x` API and has not received an independent security
audit; the bundled MLS profile is an RFC 9420 subset.

## Start a client

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
const result = await client.sync();
if (result.status === "reset") {
    // Reload every reported topic with client.loadTopic(...).
} else {
    for (const received of result.events) {
        await store.transaction(async (transaction) => {
            // Persist the authenticated application effect first.
            await received.advanceCursor(transaction);
        });
    }
}
```

`subscribe()` only follows a topic in this client instance. The relay has no
subscription or recipient queue state.

## Public API

Domain APIs are exported from the package root and matching subpaths:

| Import                     | Main API                                                                                  |
| -------------------------- | ----------------------------------------------------------------------------------------- |
| `@slopus/murmur/client`    | `MurmurClient`, `SyncResult`, `ReceivedEvent`, `PublishResult`, retained outbox retries   |
| `@slopus/murmur/crypto`    | Ed25519/X25519 identities, sealed boxes, signing, hashing, secret destruction             |
| `@slopus/murmur/identity`  | identity tokens, public first-contact inbox, `pairwiseTopic`, profiles, `ContactBook`     |
| `@slopus/murmur/messaging` | direct-message/file encryption, stable list IDs, atomic replay/cursor acceptance          |
| `@slopus/murmur/mls`       | epochs, KeyPackages, Welcome, TreeKEM Commits, applications, and `MlsGroupChannel`        |
| `@slopus/murmur/transport` | fixed relay types, canonical signed events, `HttpRelayTransport`, snapshot/list/log reads |
| `@slopus/murmur/storage`   | `MurmurStore`, `StoreTransaction`, `MemoryMurmurStore`                                    |
| `@slopus/murmur/document`  | convergent shared-text operations                                                         |

The core client surface is:

```ts
client.subscribe(topic): Promise<void>;
client.publish(topic, payload, { snapshot?, list? }?): Promise<PublishResult>;
client.publishUnlinkable(topic, payload, mutations?): Promise<PublishResult>;
client.publishEvent(event): Promise<PublishResult>;
client.retryOutboundSettled(): Promise<RetryOutboundReport>;
client.sync(waitMilliseconds?, signal?): Promise<SyncResult>;
client.loadTopic(topic, applicationTransaction, relayId?): Promise<Result>;
client.putBlob(ciphertext): Promise<RelayBlob>;
client.getBlob(id): Promise<RelayBlob | undefined>;
```

Publishing succeeds when at least one relay accepts the event. The outbox keeps
the exact signed event until every configured relay accepts it. Relay retries
return their original `seq` and `duplicate: true`.

## Cursor and reset contract

Relay sequences are local to a relay/topic pair, so the store keeps one cursor
for each pair. `ReceivedEvent.advanceCursor(transaction)` refuses to skip a
sequence. The application effect and cursor must commit in the same
`MurmurStore` transaction; rollback makes the event readable again.

`sync()` is discriminated:

- `status: "events"` contains retained events after the durable cursors.
- `status: "reset"` contains reset descriptors and no events.

A reset means the cursor is outside usable retained history. Call `loadTopic()`;
it loads the snapshot, follows every list page to `nextCursor: null`, invokes
the application callback, and installs the returned state sequence in the same
transaction. Reset is never silently interpreted as caught up.

## Identity privacy

`identityInboxTopic()` is for first contact only and is derived from a public
signing key. Anyone with the public identity token can read it. The sender
identity is sealed inside the profile payload, and `publishUnlinkable()` uses a
one-use relay signing identity. The inbox therefore leaks that N unlinkable
contact requests exist, but not who sent them.

Ongoing direct traffic uses `pairwiseTopic(self, peer)`. It derives X25519
shared secret material, domain-separates it with
`murmur/pairwise-topic/x25519-sha256/v1`, binds both encryption public keys in
lexicographic base64url order, hashes the canonical preimage, and zeros the
shared secret and preimage. Alice and Bob get the same capability; public keys
alone cannot derive it. Possession of the topic still grants read access, and
the relay still sees event authors, timing, and ciphertext sizes.

## Messages and files

Sending a chat message publishes one event with an `append` list operation
whose bytes are the same end-to-end encrypted envelope. The stable element ID
is author-scoped and derived from the application message ID. Full history is
the permanent list; the event log is only for incremental updates.

`acceptPrivateMessageFromContact()` authenticates and decrypts the envelope,
then commits the application record, message replay marker, and optional cursor
together. It reports `"opened"` or `"duplicate"` and throws on authenticated
same-ID content collisions.

Files are encrypted before blob upload. Their key and nonce stay inside
encrypted message content. The HTTP transport requests a short-lived upload or
download link from the relay and then transfers bytes with the returned URL,
method, and optional headers. Relative local-backend links and absolute S3 links
use the same browser-safe injected `fetch`.

## Relay transport

```ts
interface RelayTransport {
    readonly id: string;
    publish(event: SignedRelayEvent): Promise<PublishOutcome>;
    readState(topic: string, limit?: number): Promise<TopicState | undefined>;
    readList(topic: string, cursor?: string, limit?: number): Promise<ListPage | undefined>;
    readEvents(
        topic: string,
        since: bigint,
        limit?: number,
        wait?: number,
        signal?: AbortSignal,
    ): Promise<EventPage | undefined>;
    putBlob(blob: RelayBlob): Promise<void>;
    getBlob(id: string): Promise<RelayBlob | undefined>;
}
```

`HttpRelayTransport` accepts an injected Fetch implementation for workers and
in-process tests. Event signatures are strict Ed25519 over recursively
key-sorted canonical JSON with `signature` omitted and every `Uint8Array`
encoded as unpadded base64url.
