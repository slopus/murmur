# Murmur

Murmur is a browser-safe TypeScript library for stateful MLS sessions over one
deliberately simple relay. The relay stores unacknowledged encrypted deliveries
in one authenticated queue per public identity, plus public signed invitation
bundles in a non-enumerable five-minute cache. Durable identity, MLS epochs,
replay protection, buffered updates, application effects, and history belong to
the client application.

```text
32-byte invitation digest -> five-minute relay cache -> signed bundle
                                       |
                                       v
MurmurClient -- signed encrypted multicast --> identity queues
     |                                            |
     +-- durable MLS checkpoints/outboxes <-------+
     +-- one identity-wide ordered update loop
```

Two-person and many-person interactions use the same MLS session primitive.
There is no friendship protocol, anonymous addressing, relay-side session
state, or server-side message history.

## Packages

- `@slopus/murmur` — the only published package; ESM-only and browser-safe.
- `@slopus/murmur-relay` — private Node infrastructure with SQLite and Postgres
  stores.

## Identity and five-minute invitations

`murmur.identity` is the stable public identifier. It is exactly one 32-byte
Ed25519 public key:

```ts
const publicIdentity: Uint8Array = murmur.identity;
```

The identity alone is not enough to add a member to MLS. MLS also requires
fresh one-use HPKE and leaf material. Murmur packages that public material into
a five-minute, identity-signed `DiscoveryBundle`.

The bundle contains:

- the 32-byte public identity;
- one or more public, one-use MLS KeyPackages;
- creation and expiration times;
- an Ed25519 signature binding the complete bundle.

It contains no private key material. The matching private KeyPackage state is
persisted only in the prospective member's local `MurmurStore`.

The complete default bundle is about 645 bytes, but it does not need to be
placed in a QR code. `createInvitation()` uploads the exact signed bytes to the
relay's non-enumerable five-minute cache and returns their 32-byte SHA-256
digest. The digest is 43 characters as unpadded base64url and fits comfortably
in a small QR code or deep link.

### Implementing a digest invitation

Suppose Alice wants to add Bob:

1. Bob calls `createInvitation()`. Murmur creates a fresh KeyPackage, persists
   its private half locally for five minutes, uploads the signed public bundle,
   and returns its SHA-256 digest.
2. Bob sends only that 32-byte digest to Alice through a QR code, deep link,
   nearby exchange, or another out-of-band path.
3. Alice calls `resolveInvitation()`. Murmur downloads the exact bytes by
   digest, verifies the SHA-256 digest, signed expiry, identity signature, and
   KeyPackage signatures.
4. Alice passes the verified bundle to `createSession()` or `addMember()`.
5. Murmur creates the MLS Commit and sends Bob a sealed Welcome through Bob's
   authenticated relay queue.
6. Bob's `sync()` loop receives the Welcome. The new session becomes durable
   but remains `pending` until Bob's application activates or ignores it.

```ts
import { MemoryMurmurStore, MurmurClient } from "@slopus/murmur";

const alice = await MurmurClient.open({
    relay: "https://relay.example",
    store: new MemoryMurmurStore(),
});

const bob = await MurmurClient.open({
    relay: "https://relay.example",
    store: new MemoryMurmurStore(),
});

// Bob uploads one signed five-minute bundle and gets a 32-byte digest.
const bobInvitationDigest = await bob.createInvitation();

// The application encodes only this digest in its QR/deep link.
const scannedDigest = bobInvitationDigest;
const bobInvite = await alice.resolveInvitation(scannedDigest);

// Alice creates a two-member MLS session and publishes its Commit + Welcome.
const session = await alice.createSession({
    descriptor: new TextEncoder().encode("opaque application metadata"),
    members: [bobInvite],
});
await alice.synchronize();

// Bob durably receives a pending session, then explicitly accepts it.
await bob.synchronize();
await bob.activateSession(session.id);
```

Treat each discovery bundle as one-use:

- Generate a fresh bundle for each invitation attempt.
- Do not reuse a bundle for another session or membership operation.
- Complete the lookup and Welcome within five minutes. If either expires,
  obtain a fresh digest.
- Treat the digest as a short-lived bearer capability. It is unguessable, but
  anyone who receives it can download the public invitation bundle.
- Murmur deletes the matching private KeyPackage when its Welcome is consumed,
  or on the next client operation after expiry and before any later Welcome can
  be processed. Expired Welcomes are rejected.
- `discovery()`, `serializeDiscoveryBundle()`, and `parseDiscoveryBundle()`
  remain available when an application deliberately wants to transport the
  complete self-contained bundle without the relay cache.

Received sessions remain `pending` until the application calls
`activateSession()` or `ignoreSession()`. Pending sessions continue processing
MLS protocol state and buffer opaque application events within configured
bounds without exposing them to the application.

## One synchronization loop

`sync()` maintains the identity's one recipient-authenticated SSE connection
and streams the actual queued encrypted deliveries—not wake notifications.
Each SSE record contains the relay UUIDv7 event ID and exact sender-signed
delivery.

Application updates from every active session enter one identity-wide UUIDv7
order. Murmur passes a bounded batch to `onUpdates`. After the callback
resolves, Murmur atomically commits the whole batch locally. If it throws or
the process exits first, the same stable update IDs are offered again.

```ts
const aliceAbort = new AbortController();
const bobAbort = new AbortController();
let markDelivered!: () => void;
const delivered = new Promise<void>((resolve) => {
    markDelivered = resolve;
});

const aliceRunning = alice.sync({
    abort: aliceAbort.signal,
    onUpdates: async (updates) => {
        // Alice also receives her own session deliveries.
        applyToAliceState(updates);
    },
});
const bobRunning = bob.sync({
    abort: bobAbort.signal,
    onConnected: () => console.log("Bob connected"),
    onDisconnected: (error) => console.log("Bob disconnected", error),
    onUpdates: async (updates) => {
        // Route by update.sessionId and decode update.bytes however the app wants.
        applyToBobState(updates);
        await persistBobState();
        markDelivered(); // Murmur commits this complete batch after return.
    },
});

// Durable local outboxes wake sync() and publish automatically.
await alice.send(session.id, new TextEncoder().encode("realtime hello"));
await delivered;

// Stop during application shutdown.
aliceAbort.abort();
bobAbort.abort();
await Promise.all([aliceRunning, bobRunning]);
```

All `sync()` options are optional. Without `abort`, the loop runs until a fatal
error or process shutdown. Without `onUpdates`, application updates remain
buffered and uncommitted. Ordering is guaranteed within one identity inbox, not
across different identities. If the connection drops, Murmur calls
`onDisconnected`, reconnects from its durable cursor, and calls `onConnected`
after the next successful SSE handshake.

The relay item itself is acknowledged after Murmur durably buffers its protocol
outcome. The later `onUpdates` commit is local application handoff: it never
exposes a `MurmurStore` transaction and performs no relay round trip.
Applications that persist effects outside `MurmurStore` should use each
update's stable `id` for idempotency. `synchronize()` remains as a bounded
foreground fallback.

`MemoryMurmurStore` is for tests and examples. Production applications must
provide a durable transactional `MurmurStore`.

## Compatibility and upgrades

Murmur v0.3.3 and relay schema v3 are the compatibility baseline. Releases
after that baseline preserve the public `@slopus/murmur` API and wire formats,
and they keep persisted client state readable or migrate it. Relay schema
upgrades migrate existing databases in place without deleting pending
deliveries or requiring a clean database.

The older pre-v0.3 friendship, topic, retained-event, storage, and CLI formats
remain unsupported.

## Development

```bash
pnpm install
pnpm format
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

Read the
[architecture](https://github.com/slopus/murmur/blob/main/docs/ARCHITECTURE.md),
[protocol](https://github.com/slopus/murmur/blob/main/docs/PROTOCOL.md),
[relay API](https://github.com/slopus/murmur/blob/main/docs/RELAY_API.md), and
[security notes](https://github.com/slopus/murmur/blob/main/docs/SECURITY.md)
before integrating.

> Murmur is a `0.x` project and has not received an independent security audit.
