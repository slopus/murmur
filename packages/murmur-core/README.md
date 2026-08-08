# `@slopus/murmur`

The single published Murmur package. It is ESM-only, side-effect-free, and
browser-safe. Runtime dependencies are Noble cryptography packages only.

## Public entry

The package exposes one root import:

```ts
import {
    HttpDeliveryTransport,
    MemoryMurmurStore,
    MurmurClient,
    generateIdentityKeyPair,
} from "@slopus/murmur";
```

`MurmurClient.open` accepts either a relay URL or a custom `DeliveryTransport`,
plus an application-owned transactional `MurmurStore`. The main API covers:

- one durable public identity;
- signed one-use discovery bundles;
- creating, pending, active, and removed MLS sessions;
- explicit proposal acceptance and committer transfer;
- opaque send, activation, drain, synchronization, and durable issues.

Lower-level delivery codecs, transport, inbox processor, and store interfaces
are exported for custom hosts and storage integrations. The root also exports
the identity key lifecycle needed by those lower-level APIs. MLS internals are
not a package subpath.

## Commands

```bash
pnpm --filter @slopus/murmur check
pnpm --filter @slopus/murmur test
pnpm --filter @slopus/murmur build
```
