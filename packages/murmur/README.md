# Murmur

Murmur is a browser-safe TypeScript library for stateful MLS sessions over one
deliberately simple relay. The relay stores only unacknowledged encrypted
deliveries in one authenticated queue per public identity. Durable identity,
MLS epochs, replay protection, application effects, and history belong to the
client application.

```text
out-of-band discovery bundle
            |
            v
MurmurClient -- signed encrypted multicast --> identity queues
     |                                            |
     +-- durable MLS checkpoints/outboxes <-------+
     +-- application-owned event durability
```

Two-person and many-person interactions use the same MLS session primitive.
There is no friendship protocol, anonymous addressing, relay-side session
state, or server-side message history.

## Packages

- `@slopus/murmur` — the only published package; ESM-only and browser-safe.
- `@slopus/murmur-relay` — private Node infrastructure with SQLite and Postgres
  stores.

## Identity and self-contained invitations

`murmur.identity` is the stable public identifier. It is exactly one 32-byte
Ed25519 public key:

```ts
const publicIdentity: Uint8Array = murmur.identity;
```

The identity alone is not enough to add a member to MLS. MLS also requires
fresh one-use HPKE and leaf material. Murmur packages that public material into
a short-lived, identity-signed `DiscoveryBundle`.

The bundle contains:

- the 32-byte public identity;
- one or more public, one-use MLS KeyPackages;
- creation and expiration times;
- an Ed25519 signature binding the complete bundle.

It contains no private key material. The matching private KeyPackage state is
persisted only in the prospective member's local `MurmurStore`.

### Implementing a self-contained invitation

Suppose Alice wants to add Bob:

1. Bob calls `discovery()`. Murmur creates a fresh KeyPackage, persists its
   private half locally, and returns the signed public bundle.
2. Bob serializes and sends that bundle to Alice through the application: a QR
   code, deep link, nearby exchange, authenticated API, or another out-of-band
   path.
3. Alice strictly parses and verifies the received bytes.
4. Alice passes Bob's bundle to `createSession()` or `addMember()`.
5. Murmur creates the MLS Commit and sends Bob a sealed Welcome through Bob's
   authenticated relay queue.
6. Bob calls `synchronize()`. The new session becomes durable but remains
   `pending` until Bob's application activates or ignores it.

```ts
import {
    MemoryMurmurStore,
    MurmurClient,
    parseDiscoveryBundle,
    serializeDiscoveryBundle,
} from "@slopus/murmur";

const alice = await MurmurClient.open({
    relay: "https://relay.example",
    store: new MemoryMurmurStore(),
});

const bob = await MurmurClient.open({
    relay: "https://relay.example",
    store: new MemoryMurmurStore(),
});

// Bob creates one self-contained, signed, short-lived invitation payload.
const bobInviteBytes = serializeDiscoveryBundle(await bob.discovery());

// The application transfers bobInviteBytes to Alice out of band.
const receivedInviteBytes = bobInviteBytes;
const bobInvite = parseDiscoveryBundle(receivedInviteBytes);

// Alice creates a two-member MLS session and publishes its Commit + Welcome.
const session = await alice.createSession({
    descriptor: new TextEncoder().encode("opaque application metadata"),
    members: [bobInvite],
});
await alice.synchronize();

// Bob durably receives a pending session, then explicitly accepts it.
await bob.synchronize();
await bob.activateSession(session.id, async (transaction, event) => {
    await transaction.set("application/latest-message", event.bytes);
});

await alice.send(session.id, new TextEncoder().encode("hello Bob"));
await alice.synchronize();
await bob.synchronize();
await bob.drain(session.id, async (transaction, event) => {
    await transaction.set("application/latest-message", event.bytes);
});
```

Treat each discovery bundle as one-use:

- Generate a fresh bundle for each invitation attempt.
- Do not reuse a bundle for another session or membership operation.
- If it expires or its Welcome cannot be completed, obtain a fresh bundle.
- The bundle is public but integrity-sensitive; always use
  `parseDiscoveryBundle()` on received bytes.
- Never delete or roll back the prospective member's local KeyPackage state
  before its Welcome is processed.

Received sessions remain `pending` until the application calls
`activateSession()` or `ignoreSession()`. Pending sessions continue processing
MLS protocol state and buffer opaque application events within configured
bounds without exposing them to the application.

`MemoryMurmurStore` is for tests and examples. Production applications must
provide a durable transactional `MurmurStore`.

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
