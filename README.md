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
- `@murmur/relay` — private Node infrastructure with SQLite and Postgres
  stores.

## Minimal flow

```ts
import { MemoryMurmurStore, MurmurClient } from "@slopus/murmur";

const murmur = await MurmurClient.open({
    relay: "https://relay.example",
    store: new MemoryMurmurStore(),
});

// Share this signed bundle through a QR code, link, directory, or another
// application-owned discovery mechanism.
const myBundle = await murmur.discovery();

// A peer's bundle bootstraps a two-member MLS session.
const session = await murmur.createSession({
    descriptor: new TextEncoder().encode("opaque application metadata"),
    members: [peerBundle],
});

await murmur.synchronize();
await murmur.send(session.id, new TextEncoder().encode("opaque application event"));
await murmur.synchronize();
```

Received sessions remain `pending` until the application calls
`activateSession`. Pending sessions continue processing MLS state and buffer
opaque application events within configured bounds.

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

Read [the architecture](docs/ARCHITECTURE.md), [protocol](docs/PROTOCOL.md),
[relay API](docs/RELAY_API.md), and [security notes](docs/SECURITY.md) before
integrating.

> Murmur is a `0.x` project and has not received an independent security audit.
