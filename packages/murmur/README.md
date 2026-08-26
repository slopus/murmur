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
- The relay exposes one ordered encrypted queue per exact public identity.
  Delivery acknowledgement is signed and separate from processing.

## Install

```bash
pnpm add @slopus/murmur
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
import { MemoryMurmurStore, MurmurClient } from "@slopus/murmur";

const encode = (value: string): Uint8Array => new TextEncoder().encode(value);

const alice = await MurmurClient.open({
    relay: "https://relay.example",
    store: new MemoryMurmurStore(),
});
const bob = await MurmurClient.open({
    relay: "https://relay.example",
    store: new MemoryMurmurStore(),
});

const bobAdmission = await alice.claimAccount(bob.identity, ticket);
const session = await alice.createSession({
    descriptor: encode('{"protocol":"chat","version":1}'),
    members: [bobAdmission],
});

await alice.synchronize({ waitMilliseconds: 0 });
await bob.synchronize({ waitMilliseconds: 0 });
await bob.activateSession(session.id);

await alice.send(session.id, encode("hello"));
await alice.synchronize({ waitMilliseconds: 0 });
await bob.synchronize(
    { waitMilliseconds: 0 },
    {
        onUpdates: async (updates) => {
            for (const update of updates) {
                console.log(update.id, update.bytes);
            }
        },
    },
);

const carolAdmission = await alice.claimAccount(carolIdentity, anotherTicket);
await alice.addMember(session.id, carolAdmission);
```

Opening an HTTP-backed client automatically publishes a small one-use
KeyPackage pool and one multi-use last-resort package per device. Claims prefer
one-use packages. Their ordinary inbox spent notices trigger automatic
replenishment. `rotate()` replaces every unclaimed one-use package and the
last-resort package:

```ts
await bob.rotate();
```

For application-routed admission, `createKeyPackage()` remains available and
returns bare `{ identity, keyPackage }` material. `createSession()` and
`addMember()` accept that form too; each bare KeyPackage is one-use.

## Durable synchronization

`synchronize()` performs one bounded cycle. `sync()` keeps a persistent
reconnecting loop active:

```ts
const controller = new AbortController();

await murmur.sync({
    abort: controller.signal,
    onConnected: () => console.log("connected"),
    onDisconnected: (error) => console.log("disconnected", error),
    onUpdates: async (updates) => applyAtomically(updates),
    onDeviceAdded: async (events) => recordAddedDevices(events),
    onDeviceRevoked: async (events) => recordRevokedDevices(events),
    onDeviceDormant: async (events) => reviewDormantDevices(events),
    onReset: async (reset) => preserveApplicationMetadata(reset),
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
- `send`, `addMember`, `removeMember`, and `leaveSession`;
- `grantAdmin`, `revokeAdmin`, and `setPolicies`;
- optional typed services registered under stable IDs.

The immutable session owner is always an admin. Policy controls whether admins
may assign admins and whether every member may add another member. A committer
adopts its own Commit only after the authenticated queue echo arrives.

## Multiple devices

Restoring the same account identity on another store creates a fresh device key
and self-registers it with the relay-owned current roster:

```ts
const secondDevice = await MurmurClient.open({
    identity: restoredAccount,
    relay,
    store: secondStore,
});
await secondDevice.synchronize({ waitMilliseconds: 0 });
```

Registration and removal are account-identity-signed relay mutations. Their
ordinary inbox notifications drive MLS convergence. Any restored device may
remove itself or another device with `removeDevice(deviceKey)`. Dormancy
reporting is advisory; removal remains an explicit application decision.

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

See [relay deployment](../../docs/DEPLOYMENT.md), [relay API](../../docs/RELAY_API.md), and
the [protocol reference](../../docs/PROTOCOL.md).

## Security properties

- Noble libraries provide cryptographic primitives.
- Secret keys remain `Uint8Array` values and are zeroed when their lifetime
  ends.
- Base64url appears only at storage and wire boundaries.
- Inputs are validated before cryptographic operations.
- Relay authentication comparisons are constant-time.
- `@slopus/murmur` has no `node:*` imports or runtime side effects.

Review [SECURITY.md](../../docs/SECURITY.md) before production use.

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
