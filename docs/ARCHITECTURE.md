# Architecture

Murmur is a client-side encryption library plus a deliberately dumb relay. All
meaning lives in the client; the relay is a queue that cannot read anything it
carries.

## Layers

```text
┌─────────────────────────────────────────────────────────┐
│ application                                             │
│   decides what messages mean, owns durable storage      │
├─────────────────────────────────────────────────────────┤
│ @slopus/murmur                                          │
│   identity · contacts · direct messages · files         │
│   MLS groups · shared documents                         │
│   MurmurClient: publish, sync, acknowledge, retry       │
├─────────────────────────────────────────────────────────┤
│ RelayTransport (interface)                              │
│   HTTP today; LAN, WebRTC, Bluetooth are drop-in        │
├═════════════════════════════════════════════════════════┤  ← trust boundary
│ relay                                                   │
│   verify envelope signature · fan out · queue · blobs   │
└─────────────────────────────────────────────────────────┘
```

Everything above the trust boundary runs on the user's machine. Everything below
it is assumed hostile.

## Packages

| Package             | Published              | Role                                                                               |
| ------------------- | ---------------------- | ---------------------------------------------------------------------------------- |
| `murmur-core`       | `@slopus/murmur`       | The library. Browser-safe, no `node:*` imports, Noble-only dependencies.           |
| `murmur-mls`        | bundled into the above | MLS: TreeKEM, key schedule, KeyPackages, Commits, Welcome, epochs.                 |
| `murmur-relay`      | internal               | `RelayService` and a runtime-neutral `fetch` handler. No HTTP server, no database. |
| `murmur-relay-node` | internal               | SQLite `RelayStore` and a Node HTTP host.                                          |
| `murmur-cli`        | `murmur-chat`          | Node CLI. JSON output so agents can drive it.                                      |

The relay is split in two on purpose: `RelayService` depends only on a
`RelayStore` interface with 8 methods, so the same logic runs on SQLite, on
Postgres, or inside a Cloudflare Durable Object.

## What the relay knows

It **can** see:

- Topic identifiers (opaque hashes, but stable and linkable over time)
- Sender public keys on every envelope, because it verifies signatures
- Explicit recipient identifiers
- Message sizes and timing
- Blob sizes and content hashes

It **cannot** see:

- Any plaintext: profiles, messages, file contents, group traffic, documents
- Group membership, group names, or epoch contents
- Whether a topic carries a chat, a document, or something an application
  invented

Group traffic is indistinguishable from chat traffic at the relay: both are
opaque MLS ciphertext on the same topic. No relay code knows a document exists.

## Data flow

### Publishing

```text
publish(topic, payload, recipients?)
        │
        ├── sign envelope (Ed25519)
        ├── record in durable outbox
        └── send to every transport in parallel
                 ├── relay A: accepted ─┐
                 └── relay B: failed    ├─► success if ≥1 accepted
                                        ┘   remainder retried by retryOutbound()
```

The outbox remembers _which_ transports accepted an event, so a retry resumes
only the missing publications instead of duplicating work.

### Receiving

```text
sync() ──► pull from every transport
            │
            ├── verify signatures
            ├── merge, order, deduplicate across relays
            └── hand ReceivedEvent to the application
                     │
                     ├── application commits its own state
                     └── application calls acknowledge()
                              │
                              └── relay deletes its queued copy
```

Nothing is acknowledged automatically. An unacknowledged event is delivered
again after a restart. This is the core durability contract: **commit, then
acknowledge**. Acknowledging first turns a crash into data loss.

### Fan-out

An event either names explicit recipients or is delivered to every subscriber of
its topic. The relay inserts one delivery row per recipient, so each recipient
acknowledges independently and a slow client cannot hold up others.

Subscribing backfills: a new subscriber receives every retained event on the
topic that was not addressed to explicit recipients. Since the relay retains
everything, a client replays the log rather than fetching a snapshot.

## Storage

The library never picks a database. It requires a `MurmurStore` with atomic
transactions:

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

Transactions are not decorative. Exactly-once message acceptance, MLS epoch
checkpoints, and document state all depend on writing an application record and
a protocol marker in the same atomic unit. A store without real transactions
will silently break those guarantees.

`MemoryMurmurStore` ships for tests and examples. Real applications use
IndexedDB, SQLite, or similar.

## Retention

A topic must see activity at least once every 30 days or it is pruned. Clients
can recreate a topic and resume. Relays promise nothing about delivery; the
guarantees come from client-side acknowledgement and retry, not from relay
durability.

## Design rules

1. **The relay stays dumb.** If a change requires the relay to understand
   message content, it belongs in the client instead.
2. **The transport is replaceable.** Swapping HTTP for LAN or Bluetooth must
   change nothing above the `RelayTransport` boundary.
3. **The library stays browser-safe.** No `node:*` imports in `@slopus/murmur`.
4. **The application owns durability.** The library never decides when it is
   safe to forget a message.
