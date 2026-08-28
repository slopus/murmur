# Murmur

Murmur is a browser-safe TypeScript library for stateful, forward-secret MLS
sessions over authenticated encrypted identity queues. The application owns
storage and effects. The relay stores opaque pending deliveries and can be
discarded without becoming session state or history.

`@slopus/murmur` is the only published package. `@slopus/murmur-relay` is
private deployment infrastructure.

## Model

- One stable Ed25519 account identity is restored across devices. Each local
  store independently owns a device key used for its relay inbox and MLS leaf.
- Two-person and many-person conversations use the same RFC 9420-style MLS
  session machinery.
- Every membership or role change is an authenticated Commit.
- Application sends persist the post-ratchet epoch and exact outbox before
  publication.
- Incoming bootstraps remain pending until the application activates or ignores
  them. Protocol traffic continues and application updates remain buffered
  while pending.
- The relay exposes one ordered encrypted inbox per device, addressed by its
  canonical public key. Session sends name only the session; the relay derives
  the complete device fanout from its own membership and roster state.
  Delivery acknowledgement is signed and separate from processing.

## Install

```bash
pnpm add @slopus/murmur @steve.kite/stdlib
```

Murmur is ESM-only and requires a `MurmurStore`. `MemoryMurmurStore` is useful
for tests; production applications should provide durable secure storage.

## Account secret

Applications can protect one identity root with a 256-bit generated string and
a user password. Murmur returns one opaque blob for application-owned storage;
it stores no password, generated secret, or recovery copy itself:

```ts
import {
    createAccountSecret,
    destroyIdentity,
    generateIdentityKeyPair,
    rewrapAccountSecret,
    unlockAccountSecret,
} from "@slopus/murmur";

const identity = generateIdentityKeyPair();
const accountSecret = await createAccountSecret(identity, password);

saveBlob(accountSecret.blob);
showGeneratedSecretOnce(accountSecret.generatedSecret);

const restored = await unlockAccountSecret(
    accountSecret.blob,
    accountSecret.generatedSecret,
    password,
);

const changedBlob = await rewrapAccountSecret(
    accountSecret.blob,
    accountSecret.generatedSecret,
    password,
    newPassword,
);

destroyIdentity(restored);
```

Unlocking requires both inputs. Password changes authenticate and preserve the
complete encrypted root payload while rotating its salt and nonce. There is no
server involvement or reset path; losing either input is final.

## Directory session example

The application obtains a claim ticket from its authentication server and
names the exact account identity it already knows. The resulting account claim
is accepted directly by both session creation and member addition:

```ts
import { createRootContext } from "@steve.kite/stdlib";
import { MemoryMurmurStore, MurmurClient } from "@slopus/murmur";

const ctx = createRootContext().named("chat");
const encode = (value: string): Uint8Array => new TextEncoder().encode(value);

const alice = await MurmurClient.open(ctx, {
    relay: "https://relay.example",
    store: new MemoryMurmurStore(),
});
const bob = await MurmurClient.open(ctx, {
    relay: "https://relay.example",
    store: new MemoryMurmurStore(),
});

const bobAdmission = await alice.claimAccount(ctx, bob.identity, ticket);
const session = await alice.createSession(ctx, {
    descriptor: encode('{"protocol":"chat","version":1}'),
    members: [bobAdmission],
    sendPolicy: "admins",
});

await alice.synchronize(ctx, { waitMilliseconds: 0 });
await bob.synchronize(ctx, { waitMilliseconds: 0 });
await bob.activateSession(ctx, session.id);

await alice.send(ctx, session.id, encode("hello"));
await alice.synchronize(ctx, { waitMilliseconds: 0 });
await bob.synchronize(
    ctx,
    { waitMilliseconds: 0 },
    {
        onUpdates: async (_ctx, updates) => {
            for (const update of updates) {
                console.log(update.id, update.bytes);
            }
        },
    },
);

const carolAdmission = await alice.claimAccount(ctx, carolIdentity, anotherTicket);
await alice.addMember(ctx, session.id, carolAdmission);
```

Opening an HTTP-backed client automatically publishes a small one-use
KeyPackage pool and one multi-use last-resort package per device. Claims prefer
one-use packages. Their ordinary inbox spent notices trigger automatic
replenishment. `rotate()` replaces every unclaimed one-use package and the
last-resort package:

```ts
await bob.rotate(ctx);
```

For application-routed admission, `createKeyPackage()` remains available and
returns bare `{ identity, keyPackage }` material. `createSession()` and
`addMember()` accept that form too; each bare KeyPackage is one-use.

## Durable synchronization

`synchronize()` performs one bounded cycle. `sync()` keeps a persistent
reconnecting loop active:

```ts
const controller = new AbortController();

await murmur.sync(ctx, {
    abort: controller.signal,
    onConnected: (_ctx) => console.log("connected"),
    onDisconnected: (_ctx, error) => console.log("disconnected", error),
    onUpdates: async (_ctx, updates) => applyAtomically(updates),
    onDeviceAdded: async (_ctx, events) => recordAddedDevices(events),
    onDeviceRevoked: async (_ctx, events) => recordRevokedDevices(events),
    onDeviceDormant: async (_ctx, events) => reviewDormantDevices(events),
    onReset: async (_ctx, reset) => preserveApplicationMetadata(reset),
});
```

Murmur drains an application-update batch only after `onUpdates` resolves.
Throwing leaves the same durable batch available for retry. Stable relay event
IDs support application-level idempotency.

## Sessions

The application owns opaque descriptors and update bytes. Murmur exposes:

- `createSession`, `session`, and bounded `sessions` listing;
- `claimAccount` and explicit directory `rotate`;
- `activateSession`, `ignoreSession`, and `abandonSession`;
- `send`, `addMember`, `removeMember`, `leaveSession`, and owner-only
  `deleteSession`;
- terminal `deleteAccount`;
- `grantAdmin`, `revokeAdmin`, and `setPolicies`;
- optional typed services registered under stable IDs.

The immutable session owner is always an admin. Policy controls whether admins
may assign admins, whether every member may add another member, and whether
everyone or only admins may send application events. Only the owner may change
policy or terminally delete the session. A committer adopts its own Commit only
after the authenticated queue echo arrives.

## Multiple devices

Restoring the same account identity on another store creates a fresh device key
and self-registers it with the relay-owned current roster:

```ts
const secondDevice = await MurmurClient.open(ctx, {
    identity: restoredAccount,
    relay,
    store: secondStore,
    encryptDeviceMetadata: (_ctx, deviceKey) => encryptLocalDeviceMetadata(deviceKey),
});
await secondDevice.synchronize(ctx, { waitMilliseconds: 0 });
```

Registration and removal are account-identity-signed relay mutations. Their
ordinary inbox notifications drive MLS convergence. Any restored device may
remove itself or another device with `removeDevice(ctx, deviceKey)`. Dormancy
reporting is advisory; removal remains an explicit application decision.

An application may attach up to 16 KiB of owner-encrypted metadata to each
roster entry. Murmur supplies the stable device key to `encryptDeviceMetadata`
so the ciphertext can be bound to that exact account/device pair, but neither
Murmur nor the relay decrypts it. `devices(ctx)` returns defensive copies of the
opaque bytes and refreshes the roster from the relay. Each entry also carries
`lastAccessedAt`, the relay-owned time when that device most recently received
a session token. Token issuance updates this timestamp monotonically without
advancing the cryptographic roster revision. Reopening with changed ciphertext
updates only metadata: the device key, reset generation, access time, directory
material, and MLS membership remain unchanged. Omitting the callback preserves
an existing value.

While `sync()` is connected, the relay sends an owner-only roster invalidation
to every current account device stream after registration, removal, metadata
change, or access-time change. Murmur reads the authoritative roster, updates
its local observation, and invokes `onDevicesChanged` with defensive copies.
The notification carries no metadata and is deliberately ephemeral; durable
device additions and removals still arrive through the ordered inbox.

`deleteAccount(ctx)` is terminal. It persists and retries one signed relay request,
then clears every local store key and destroys both identity roots only after
relay confirmation. It does not erase authenticated MLS events already held by
other members; those members converge later through silence or explicit
removal.

## Storage and recovery

The store contains identity roots, MLS epochs, pending bootstraps, replay state,
outboxes, account state, and queue progress. Treat it as secret application
state and back it up atomically. Losing it loses cryptographic session state.

If relay continuity is lost, Murmur records a final reset snapshot and calls
`onReset`. Resolving that callback authorizes the one-time technical-state
purge; application data remains application-owned.

## Relay

The standalone relay and Cloudflare Worker transport opaque signed deliveries.
They do not parse MLS or retain conversation history. Production ingress must
provide non-Sybil admission because public identities are inexpensive to
create.

See [relay deployment](docs/DEPLOYMENT.md), [relay API](docs/RELAY_API.md), and
the [protocol reference](docs/PROTOCOL.md).

## Security properties

- Noble libraries provide cryptographic primitives.
- Secret keys remain `Uint8Array` values and are zeroed when their lifetime
  ends.
- Base64url appears only at storage and wire boundaries.
- Inputs are validated before cryptographic operations.
- Relay authentication comparisons are constant-time.
- `@slopus/murmur` has no `node:*` imports or runtime side effects.

Review [SECURITY.md](docs/SECURITY.md) before production use.

## Development

```bash
pnpm install
pnpm test
pnpm typecheck
pnpm lint
pnpm format:check
pnpm build
```

Node 22.5 or later is required for the SQLite relay. The published library
supports Node 20 or later and browser runtimes with the required Web APIs.
