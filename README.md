# Murmur

Murmur is one browser-safe stateful library for encrypted friend bootstrap and
opaque MLS group event streams over one deliberately dumb relay.

```text
application
    |
    | MurmurStore
    v
@slopus/murmur ---- exactly one relay ---- ordered signed opaque events
    |
    +-- one identity and profile
    +-- encrypted friend requests and control channels
    `-- MLS groups with opaque descriptors and application bytes
```

Murmur owns identity secrets, friend lifecycle, relay cursors, exact outboxes,
KeyPackages, invitations, MLS epochs, replay, and crash recovery. The
application supplies transactional persistence and decides what descriptors and
events mean.

```ts
import { MemoryMurmurStore, Murmur } from "@slopus/murmur";

const murmur = await Murmur.open({
    relay: "https://relay.example",
    store: new MemoryMurmurStore(),
    initialProfile: { name: "Alice" },
});

await murmur.friends.request(bobIdentityKey);

const groupId = await murmur.groups.create(applicationDescriptor, [bobIdentityKey]);
await murmur.groups.send(groupId, applicationBytes);

// Optional when the application needs an explicit observed boundary:
await murmur.sync({ waitMilliseconds: 5_000 });

await murmur.close();
```

`MemoryMurmurStore` is for tests and examples. Production applications provide
a durable `MurmurStore` whose transaction callback is genuinely atomic.

The published package has one import path: `@slopus/murmur`. Relay topics,
cursors, Welcome messages, KeyPackages, epoch checkpoints, and publish/adopt
choreography are internal.

`Murmur.open()` starts an internal convergence worker. Mutations wake it and
durable failures are retried with backoff; `sync()` remains available for
tests, shutdown coordination, or an application-requested observation point.

> Murmur is a `0.x` project and has not received an independent security audit.
> Its MLS code is a tested RFC 9420 subset, not a complete interoperable MLS
> implementation.
