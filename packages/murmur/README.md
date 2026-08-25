# Murmur

[![npm](https://img.shields.io/npm/v/%40slopus%2Fmurmur)](https://www.npmjs.com/package/@slopus/murmur)
[![license](https://img.shields.io/npm/l/%40slopus%2Fmurmur)](https://github.com/slopus/murmur/blob/main/LICENSE)

Murmur is a browser-safe TypeScript library for stateful [MLS](https://www.rfc-editor.org/rfc/rfc9420)
sessions over one deliberately simple relay. Two identities discover each
other through a short-lived signed invitation, bootstrap a forward-secret MLS
session, and exchange end-to-end encrypted data through typed synchronization
services. A two-person conversation and a many-person group use the same
session primitive.

The relay is a disposable delivery buffer: one authenticated encrypted queue
per public identity plus a non-enumerable five-minute invitation cache. All
durable protocol state — identity secrets, MLS epochs, replay protection,
outboxes, and contacts — lives in storage the application supplies. The
application separately owns its history and effects.

**Murmur is:**

- a stateful client library with one durable identity per store;
- end-to-end encrypted with MLS (TreeKEM) for two or more members;
- built-in mutual-profile contacts plus optional typed services;
- multi-device: one account links independently keyed devices through a
  signed roster, and session membership converges automatically;
- offline-first, with durable outboxes and restart-safe delivery.

**Murmur is not:**

- anonymous: the relay learns sender, recipient, fanout, and timing metadata;
- server-side history: acknowledged deliveries are gone from the relay;
- a recovery system: losing the local store loses sessions and contacts.

```text
                      out-of-band (QR, deep link, ...)
     Bob ---------------- 32-byte invitation digest ---------------> Alice
      |                                                               |
      | upload signed bundle                        fetch + verify    |
      v                                                               v
+---------------------------- relay (untrusted) ----------------------------+
|  five-minute invitation cache        one encrypted queue per identity     |
|  (content-addressed by SHA-256)      (UUIDv7-ordered, ack-trimmed)        |
+---------------------------------------------------------------------------+
      ^                    |  atomic multicast to every member  ^
      | publish + ack      v  (SSE stream or paged read)        | publish + ack
+-------------+                                          +-------------+
| MurmurClient|  <-- MLS Welcome / Commits / app data --> | MurmurClient|
|  MurmurStore|      (encrypted; relay never decrypts)    |  MurmurStore|
+-------------+                                          +-------------+
      |                                                        |
      +-- one identity-wide sync loop: contacts, services, onUpdates
```

- [Install](#install)
- [Five-minute tour](#five-minute-tour)
- [Durable storage: `MurmurStore`](#durable-storage-murmurstore)
- [Identity](#identity)
- [Invitations and discovery](#invitations-and-discovery)
- [Contacts](#contacts)
- [Build a group messenger](#build-a-group-messenger)
- [Sessions](#sessions)
- [Multiple devices](#multiple-devices)
- [Typed synchronization services](#typed-synchronization-services)
- [The synchronization loop](#the-synchronization-loop)
- [Durability, offline use, and idempotency](#durability-offline-use-and-idempotency)
- [Graceful shutdown](#graceful-shutdown)
- [Security and trust model](#security-and-trust-model)
- [Running a relay locally](#running-a-relay-locally)
- [Development](#development)
- [Protocol versions](#protocol-versions)

## Install

```bash
pnpm add @slopus/murmur
```

`@slopus/murmur` is ESM-only, side-effect-free, and browser-safe. It runs in
modern browsers and Node.js 20 or later, and its only runtime dependencies are
the audited Noble cryptography libraries (`@noble/curves`, `@noble/hashes`,
`@noble/ciphers`). There are no `node:*` imports and no native modules.

The repository also contains `@slopus/murmur-relay`, the private relay
infrastructure package. It is not published; you deploy it yourself or run it
locally for development (see [Running a relay locally](#running-a-relay-locally)).

## Five-minute tour

Alice and Bob become contacts. This example uses the in-memory store and a
local relay; the rest of this guide expands each step and shows how contacts
then use typed services.

```ts
import { MemoryMurmurStore, MurmurClient } from "@slopus/murmur";

const alice = await MurmurClient.open({
    relay: "http://127.0.0.1:8787",
    store: new MemoryMurmurStore(),
});
const bob = await MurmurClient.open({
    relay: "http://127.0.0.1:8787",
    store: new MemoryMurmurStore(),
});

// 1. Alice uploads a signed five-minute invitation bundle to the relay and
//    shares only its 32-byte SHA-256 digest with Bob, out of band.
const digest = await alice.createInvitation();

// 2. Bob resolves the digest, verifies the bundle, creates the two-person
//    contact session, and queues his encrypted profile hello.
await bob.requestContact(digest, { displayName: "Bob" });

// 3. Each bounded cycle publishes outboxes and receives queued deliveries.
//    Alice explicitly accepts the validated request by sending her own hello.
let accepted = false;
for (let attempt = 0; attempt < 5; attempt += 1) {
    await bob.synchronize();
    await alice.synchronize(
        {},
        {
            onContactRequested: async (requests) => {
                for (const request of requests) {
                    console.log("request from", request.profile.displayName);
                    if (!accepted) {
                        await alice.acceptContact(request.sessionId, {
                            displayName: "Alice",
                        });
                        accepted = true;
                    }
                }
            },
        },
    );
    if ((await alice.contacts()).length === 1 && (await bob.contacts()).length === 1) {
        break;
    }
}

console.log((await alice.contacts())[0]!.profile.displayName); // Bob
console.log((await bob.contacts())[0]!.profile.displayName); // Alice
```

`synchronize()` is the bounded foreground form of the sync loop, convenient
for scripts and tests. Real applications run the persistent `sync()` loop
instead, which keeps one authenticated SSE connection open and delivers
everything through the same callbacks — see
[The synchronization loop](#the-synchronization-loop).

`MemoryMurmurStore` is for tests and examples only: it forgets everything on
restart, and with it a crash loses your sessions permanently. Production
applications must supply a durable transactional store, which is the next
section.

## Durable storage: `MurmurStore`

Murmur never talks to a database itself. The application supplies one
`MurmurStore`, an atomic ordered string-key/byte-value interface, and Murmur
keeps everything durable inside it under Murmur-owned key namespaces: the
identity root, MLS epochs and ratchet checkpoints, KeyPackages, pending
sessions, contacts, session routing, outboxes, and replay/queue progress.

```ts
interface MurmurStore {
    get(key: string): Promise<Uint8Array | undefined>;
    set(key: string, value: Uint8Array): Promise<void>;
    delete(key: string): Promise<void>;
    /** @deprecated Implement for compatibility; Murmur production paths use scan. */
    list(prefix: string): Promise<ReadonlyMap<string, Uint8Array>>;
    /** One bounded lexicographically ordered page of entries under a prefix. */
    scan(
        prefix: string,
        options: { after?: string; limit: number },
    ): Promise<ReadonlyMap<string, Uint8Array>>;
    /** Run one callback atomically with rollback on throw. No nesting. */
    transaction<Result>(
        operation: (transaction: StoreTransaction) => Promise<Result>,
    ): Promise<Result>;
}
```

The contract that matters:

- **Transactions are atomic and serialized.** Everything written inside
  `transaction()` commits together or not at all, and a thrown callback rolls
  back. Murmur's crash-safety guarantees rest entirely on this.
- **`scan` is ordered.** It returns at most `limit` entries (up to
  `MAXIMUM_STORE_SCAN_ITEMS`, 10,000) in lexicographic key order, strictly
  after the optional `after` key.
- **Values are bytes.** Return defensive copies; Murmur zeroes buffers it no
  longer needs.

Use a durable adapter appropriate for your runtime. Treat the store as the
Murmur identity itself: back it up as a whole, never share it between two live
clients, and never hand-edit Murmur's keys. Custom services do not receive or
store application state in `MurmurStore`; they own any persistence separately.

## Identity

A Murmur identity is one 32-byte Ed25519 public key derived, together with its
X25519 agreement key, from one 32-byte secret root. The public key is the
stable identifier and the address of the identity's relay queue.

`MurmurClient.open()` manages the identity for you:

```ts
import { MurmurClient } from "@slopus/murmur";

const murmur = await MurmurClient.open({
    relay: "https://relay.example",
    store,
});

const publicIdentity: Uint8Array = murmur.identity; // 32-byte Ed25519 key
```

For an application-authenticated WebSocket endpoint, pass a session provider
instead of the legacy relay URL:

```ts
import { HttpRelaySessionProvider, MurmurClient } from "@slopus/murmur";

const sessionProvider = new HttpRelaySessionProvider("https://app.example/murmur/session", {
    fetch: authenticatedFetch,
});

const murmur = await MurmurClient.open({ sessionProvider, store });
```

The application endpoint returns a short-lived token, the selected
`murmur-websocket-v1` protocol, and a `wss:` endpoint. Each physical device must
use its own Murmur store and identity root. Multi-device accounts authorize
several independent device identities; those devices participate in MLS as
ordinary distinct members rather than sharing sender state.

- An empty store gets a freshly generated identity, persisted in the store.
- An existing store reuses its stored identity.
- To create an identity ahead of time or perform a key-only restore, pass one
  explicitly. `open()` copies it and throws if it differs from an identity
  already in the store.

```ts
import { destroyIdentity, generateIdentityKeyPair, importIdentityKeyPair } from "@slopus/murmur";

const identity = generateIdentityKeyPair();
// identity.secretKey is the 32-byte root: make your protected backup here.
const murmur = await MurmurClient.open({ relay, store, identity });
destroyIdentity(identity); // open() copied it; zero the caller-owned original.

// Key-only restore into a fresh store:
const restored = importIdentityKeyPair(backedUpSecretRoot);
const restoredClient = await MurmurClient.open({
    relay,
    store: freshStore,
    identity: restored,
});
destroyIdentity(restored);
```

A backed-up secret root restores the _key_, not the state. MLS epochs live
only in the store, and the relay keeps no history, so importing the root into
a fresh store yields an identity that owns its queue but has no sessions or
contacts. Real recovery means restoring the whole `MurmurStore` backup or
being invited into sessions again. After a full-store restore, simply call
`open()` with that restored store; its identity is already present.

Other `MurmurClientOptions`:

- `relay` — the relay base URL. Alternatively pass a custom `transport`
  (`DeliveryTransport`); exactly one of `relay` or `transport` is required.
  Custom-transport users must also pass `discoveryTransport` to use
  `createInvitation()`, `resolveInvitation()`, or `requestContact()`.
- `fetch` — a fetch implementation override for the built-in HTTP transports.
- `services` — typed synchronization services, described below.
- `limits` — `MurmurSessionLimits` bounds on pending sessions, buffered
  events/bytes per session, members per session, delivery ciphertext size, and
  durable outboxes.
- `now` — a clock override, useful in tests.

## Invitations and discovery

Knowing an identity key is not enough to start an MLS session: MLS also needs
fresh one-use public KeyPackage material. Murmur packages both into a signed
`DiscoveryBundle` containing the 32-byte identity, one one-use MLS KeyPackage,
creation and expiry times, and an Ed25519 signature over the whole bundle. A
bundle is valid for at most five minutes and contains no secrets; the matching
private KeyPackage state stays in the owner's local store.

The usual flow never ships the bundle itself. `createInvitation()` uploads its
exact signed bytes to the relay's content-addressed cache and returns their
32-byte SHA-256 digest. Your application can encode those bytes as 43
unpadded-base64url characters for a QR code or deep link:

```ts
// Alice, the inviter:
const digest: Uint8Array = await alice.createInvitation();
// encode those 32 bytes into your QR code / deep link / message

// Bob, after receiving the digest out of band:
await bob.requestContact(digest, { displayName: "Bob" });
```

Every invitation created through Murmur's built-in HTTP discovery transport is
registered with a separate durable revocation authority. Its private key stays
only in Alice's `MurmurStore`; neither the invitation nor its digest contains
it. Alice can invalidate one invitation or every still-live invitation created
by this store:

```ts
await alice.revokeInvitation(digest);
await alice.revokeInvitations();
```

Both operations are idempotent. A successful call removes the relay cache row,
leaves an expiring anti-resurrection tombstone, and destroys matching unused
private KeyPackages locally. A digest holder cannot revoke: the relay requires
a signature from the private revocation authority registered by the invitation
owner. Revocation does not tear down a session that already completed its
Welcome.

Revocation requires a reachable compatible discovery relay. If the request
fails, Murmur still destroys the local one-use KeyPackage and durably remembers
the pending revocation for retry after restart, so a later Welcome cannot
establish a new session. The public bundle may nevertheless continue resolving
from the relay until the authenticated retry succeeds or its five-minute expiry
arrives. Applications must treat a rejected revocation call as not yet globally
visible. Custom discovery transports support revocation only when they
implement both `uploadOwned` and `revoke`; legacy `upload`-only invitations
cannot be revoked through Murmur.

`resolveInvitation()` downloads the exact bytes by digest and verifies the
SHA-256 match, the identity signature, the signed expiry, and the KeyPackage
signatures before returning. The relay cannot enumerate cached bundles or look
them up by identity — the digest is the only lookup capability, and it expires
within five minutes of upload.

Treat every invitation as one-use and short-lived:

- Generate a fresh invitation for each initial contact attempt. Established
  contacts exchange later group-admission material automatically.
- Complete resolution and the Welcome within five minutes; if either side
  times out, start over with a fresh digest.
- The digest is an unguessable but bearer capability: anyone holding it can
  fetch the public bundle and attempt a bootstrap. The recipient always stays
  in control of acceptance.
- Murmur deletes the private KeyPackage state when its Welcome is consumed.
  Expired state becomes unusable at expiry, is pruned on the next client
  operation, and cannot accept an expired Welcome.

When an application wants to transport the complete self-contained bundle
without the relay cache (a local network exchange, a file), use `discovery()`
with `serializeDiscoveryBundle()` and `parseDiscoveryBundle()` instead.

## Contacts

Contacts are built into Murmur. A confirmed contact is durable cryptographic
proof that two identities exchanged and accepted profiles inside one
two-person technical MLS session. That session is contact and control state —
chat and other application traffic belong in services with their own sessions.

Continuing the walkthrough: Alice invited Bob with a digest, and Bob requests
the contact by attaching an application-defined JSON profile:

```ts
const session = await bob.requestContact(digest, {
    displayName: "Bob",
    avatarUrl: "https://example.com/bob.png",
});
```

On Alice's side, Murmur decrypts and validates Bob's hello while the contact
session is still pending, then surfaces the claimed profile for an explicit
decision. Nothing is activated and no raw update is delivered first:

```ts
await alice.sync({
    onContactRequested: async (requests) => {
        for (const request of requests) {
            // request.identity, request.sessionId, request.profile
            if (looksLegitimate(request.profile)) {
                await alice.acceptContact(request.sessionId, { displayName: "Alice" });
            } else {
                await alice.rejectContact(request.sessionId);
            }
        }
    },
    onContactAdded: async (added) => {
        for (const { contact } of added) {
            console.log("confirmed contact", contact.profile.displayName);
        }
    },
    onContactUpdated: async (updated) => {
        for (const { contact } of updated) {
            console.log("updated contact", contact.profile.displayName);
        }
    },
    onContactRemoved: async (removed) => {
        for (const { identity } of removed) {
            console.log("contact removed");
        }
    },
});
```

- `acceptContact(sessionId, profile)` sends Alice's own typed hello. Only the
  mutual hello exchange confirms the contact; both sides then observe
  `onContactAdded`.
- `rejectContact(sessionId)` destroys the pending contact session and its
  secrets. The requester is not notified.
- `removeContact(identity)` queues an authenticated removal through the
  technical session; the contact's status is `"removing"` until the removal
  echoes back, then `onContactRemoved` fires.

Reads are durable, local, and work fully offline:

```ts
const everyone = await murmur.contacts(); // confirmed contacts
const one = await murmur.contact(identityKey); // or undefined
const incoming = await murmur.contactRequests(); // awaiting this identity's decision
const outgoing = await murmur.outgoingContactRequests(); // awaiting the remote decision
```

Each contact carries both profiles (`localProfile` and `profile`) plus the
identity key and the technical `sessionId`. Profiles are validated,
size-bounded JSON; their schema beyond that is yours. Outgoing requests are
durable and survive reopening the same store. Repeating `requestContact()` for
an identity that already has an outgoing handshake returns that existing
session instead of creating another request.

Replace the profile visible to every established contact with one atomic
operation:

```ts
await murmur.updateContactProfile({
    displayName: "Alice",
    avatarUrl: "https://example.com/alice-v2.png",
});
```

The new local profile, a monotonic revision, and one authenticated MLS outbox
per active contact commit in the same store transaction. Publication therefore
survives disconnection and restart. Recipients durably replace `contact.profile`
and receive `onContactUpdated`; duplicate or reordered revisions are ignored.
Contacts already removed or in the `"removing"` state are not targeted.

## Build a group messenger

A messenger is one typed service plus one service-owned MLS session per
conversation. Contacts are the address book and admission layer; the technical
contact session itself is never used for chat.

Murmur and the chat service own different parts:

| Murmur owns                          | Your chat service owns                          |
| ------------------------------------ | ----------------------------------------------- |
| identity keys and confirmed contacts | group title and application group ID            |
| cached offline group-admission keys  | message packet schema                           |
| MLS epochs and membership changes    | message persistence and pagination              |
| encrypted outboxes, replay, and sync | edits, reactions, receipts, and ordering policy |

### 1. Implement the service

This minimal service claims descriptors for `chat.v1`, validates text-message
packets, and hands them to the application with the stable relay event ID.
Applications that persist messages should deduplicate on `update.id`.

```ts
import {
    type MurmurService,
    type MurmurServiceSessionDescriptor,
    type MurmurUpdate,
} from "@slopus/murmur";

const CHAT_SERVICE_ID = "chat.v1";
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

type ChatGroup = {
    version: 1;
    service: "chat";
    groupId: string;
    title: string;
};

type ChatPacket = {
    version: 1;
    type: "message";
    messageId: string;
    sentAt: number;
    text: string;
};

type ReceivedChatMessage = ChatPacket & {
    eventId: string;
    session: string;
    sender: string;
};

interface ChatApplication {
    onGroup(session: string, group: ChatGroup): void | Promise<void>;
    onMessage(message: ReceivedChatMessage): void | Promise<void>;
}

declare const chatApplication: ChatApplication;

function bytesKey(bytes: Uint8Array): string {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function encodeJson(value: ChatGroup | ChatPacket): Uint8Array {
    return encoder.encode(JSON.stringify(value));
}

function decodeObject(bytes: Uint8Array): Record<string, unknown> | undefined {
    try {
        const value: unknown = JSON.parse(decoder.decode(bytes));
        return value !== null && typeof value === "object" && !Array.isArray(value)
            ? (value as Record<string, unknown>)
            : undefined;
    } catch {
        return undefined;
    }
}

function decodeGroup(bytes: Uint8Array): ChatGroup | undefined {
    const value = decodeObject(bytes);
    return value?.version === 1 &&
        value.service === "chat" &&
        typeof value.groupId === "string" &&
        value.groupId.length > 0 &&
        typeof value.title === "string" &&
        value.title.length <= 120
        ? (value as ChatGroup)
        : undefined;
}

function decodePacket(bytes: Uint8Array): ChatPacket | undefined {
    const value = decodeObject(bytes);
    return value?.version === 1 &&
        value.type === "message" &&
        typeof value.messageId === "string" &&
        typeof value.sentAt === "number" &&
        Number.isSafeInteger(value.sentAt) &&
        typeof value.text === "string" &&
        value.text.length <= 4_000
        ? (value as ChatPacket)
        : undefined;
}

class ChatService implements MurmurService {
    constructor(private readonly application: ChatApplication) {}

    async onNewSession(session: MurmurServiceSessionDescriptor): Promise<boolean> {
        const group = decodeGroup(session.descriptor);
        if (group === undefined) return false;
        await this.application.onGroup(bytesKey(session.id), group);
        return true; // claims and activates this incoming session
    }

    async onUpdate(update: MurmurUpdate): Promise<void> {
        const packet = decodePacket(update.bytes);
        if (packet === undefined) return; // unsupported packets have no effect
        await this.application.onMessage({
            eventId: update.id,
            session: bytesKey(update.sessionId),
            sender: bytesKey(update.sender),
            ...packet,
        });
    }
}
```

Connect the service to your application, register it before synchronization
starts, and let the application persist messages however it chooses. Murmur
does not provide or pass storage to the service:

```ts
const chat = new ChatService(chatApplication);

const murmur = await MurmurClient.open({
    relay: "https://relay.example",
    store,
    services: [{ id: CHAT_SERVICE_ID, service: chat }],
});

const abort = new AbortController();
const running = murmur.sync({ abort: abort.signal });
```

Every participant must register the same service ID. An incoming descriptor
that `onNewSession` accepts is automatically activated and durably assigned to
that service.

### 2. Start a group with N people

First establish ordinary Murmur contacts. Contact hellos automatically exchange
fifteen one-use MLS KeyPackages plus a reusable last-resort package. Murmur
refills that inventory in the background, so starting a group does not require
the other people to be online or exchange new invitation links.

For N total people, the creator supplies the identities of the other N−1
confirmed contacts:

```ts
const descriptor: ChatGroup = {
    version: 1,
    service: "chat",
    groupId: globalThis.crypto.randomUUID(),
    title: "Weekend plans",
};

// Alice + Bob + Carol = a three-person MLS group.
const group = await alice.createSession({
    descriptor: encodeJson(descriptor),
    contacts: [bobIdentity, carolIdentity],
    service: CHAT_SERVICE_ID,
});

// onNewSession runs only for receivers, so the creator records local metadata.
await chatApplication.onGroup(bytesKey(group.id), descriptor);
```

`createSession()` consumes one cached admission package per contact and
durably queues the Welcomes. Bob and Carol may be completely offline. Normal
packages are one-use; refill begins at five remaining. If the fifteen-package
pool is exhausted before a response arrives, Murmur reuses that contact's
last-resort package and keeps requesting a rotated inventory. Group creation
does not wait for the contact to reconnect.

### 3. Send and receive messages

The application encodes its typed packet and sends it through the group
session:

```ts
const message: ChatPacket = {
    version: 1,
    type: "message",
    messageId: globalThis.crypto.randomUUID(),
    sentAt: Date.now(),
    text: "Dinner at seven?",
};

await alice.send(group.id, encodeJson(message));
```

`send()` only needs Murmur's local durable state. The running sync loop
publishes the outbox when connected. Every member, including Alice, receives
the encrypted echo through `ChatService.onUpdate`, so `ChatApplication` handles
sent and received messages through one path.

Service-owned updates are also visible in global `onUpdates` with
`update.service === "chat.v1"`. Treat that as observation; do not apply the
message a second time there.

### 4. Change membership

Adding another confirmed contact also consumes its cached admission material
and works while that contact is offline:

```ts
await alice.addMember(group.id, daveIdentity);
await alice.removeMember(group.id, carolIdentity);
```

Each call persists an asynchronous membership intent and returns before relay
I/O. During synchronization, any eligible current member can produce the next
role-authorized Commit. Shared relay event order resolves concurrent Commits,
and a losing intent retries against the winning epoch.

Relay order is defined per identity inbox, not globally across every member.
For a basic messenger, local inbox order is enough. If concurrent messages must
render in exactly the same order everywhere, put a Lamport counter or another
deterministic merge rule in `ChatPacket`; that policy belongs to the chat
service rather than Murmur.

## Sessions

Everything conversational in Murmur — two-person or group — is one MLS
session. A session has an opaque `descriptor` (application-defined bytes that
name what the session is for), a member list of account identity keys, one
immutable owner account, an admin set, and owner-controlled policies.

### Creating a session

Creating a session takes the descriptor and at least one confirmed contact.
Murmur consumes cached admission material, creates the MLS group, commits the
adds, and publishes each new member's encrypted Welcome to their authenticated
relay queue:

```ts
const session = await alice.createSession({
    descriptor: new TextEncoder().encode("notes/v1"),
    contacts: [bobIdentity, carolIdentity],
    adminsAssignAdmins: false,
    anyoneCanAddMembers: false,
    service: "notes", // optional: durably owned by this registered service
});
// session.id, session.status, session.members, session.owner,
// session.admins, session.policies
```

The creator account is the immutable owner and is always an admin. Both
policies default to `false`. Publication happens through the durable outbox:
`createSession` returns once the session and its outbound work are persisted,
and the sync loop performs the actual relay round trips.

### Receiving a session

A valid inbound Welcome becomes a durable _pending_ session before its relay
item is acknowledged, and Murmur routes it:

- A two-person session with the contact descriptor goes to the built-in
  contact flow above.
- Any other new session is offered to registered services through
  `onNewSession`. A claim activates the session and durably routes all later
  updates to that service. If services are registered and every one declines,
  the session is durably ignored so it can never block the identity inbox.
- With no services registered, the session stays pending and the application
  decides explicitly:

```ts
await bob.activateSession(session.id); // start receiving its updates
await bob.ignoreSession(session.id); // terminally reject and destroy it
```

While pending, Murmur keeps processing the session's MLS protocol traffic so
its epoch stays current, and buffers its application events within the
configured bounds without exposing them. Activation releases the buffered
events through the ordinary sync loop; ignoring (or overflowing the pending
bound) destroys the pending secrets and buffered data while keeping enough
replay state to make retries harmless.

### Sending data

```ts
const deliveryId = await alice.send(session.id, encodePacket(payload));
```

`send` persists the encrypted delivery in the durable outbox and returns; the
sync loop publishes it as one atomic multicast to every current member's
queue, including Alice's own. Every member — the sender included — adopts the
delivery from its authenticated queue echo, which is why senders also see
their own messages in `onUpdates`. Payload bytes are opaque to Murmur and the
relay; versioned typed encoding is the application's or service's job.

Do not wait for `session.status === "active"` before sending. `send()` also
works immediately after `createSession()` and while a membership Commit from
`addMember()` or `removeMember()` is still staged. Murmur encrypts those
packets with the staged post-Commit epoch, advances that ratchet durably, and
records the dependency. Once connected, it publishes older current-epoch work,
any required Welcomes, the Commit, and then dependent packets. If another
Commit wins first, Murmur re-encrypts dependent sends against the winning epoch
and retries the intent. The whole sequence survives a restart.

### Membership, roles, and concurrent Commits

```ts
await alice.addMember(session.id, daveIdentity);
await alice.removeMember(session.id, carolIdentity); // 32-byte identity key
await alice.grantAdmin(session.id, bobIdentity);
await alice.revokeAdmin(session.id, bobIdentity);
await alice.setPolicies(session.id, {
    adminsAssignAdmins: true,
    anyoneCanAddMembers: false,
});
await bob.leave(session.id);
```

These APIs durably record an intent and return before network convergence. The
owner cannot be removed or demoted. Admins remove other accounts; any non-owner
may leave. Admins add accounts unless `anyoneCanAddMembers` is enabled. Only the
owner revokes admins and changes policies; with `adminsAssignAdmins`, an admin
may also grant admin to a current member.

Role state is authenticated inside every Commit and Welcome. Any current
member may publish a Commit it is authorized to make, and every recipient
validates it against the prior epoch's roles. For concurrent Commits extending
one epoch, the first valid shared relay event ID wins everywhere. A publisher
also adopts only from its queue echo; a loser cancels its staged epoch,
re-encrypts dependent sends, and retries its durable intent. Concurrent adds of
one account become a no-op after the first succeeds. A stale add created before
observing that account's removal becomes a durable issue; explicitly adding
again after observing removal is permitted.

`abandonSession(id)` destroys a session stuck on a blocked local membership
operation, and `issues()` lists durable session and publication diagnostics.
`session(id)` and `sessions({ after, limit })` read local session state.

## Multiple devices

One account can run several devices. The account identity is a signing key
only: it signs a versioned, replay-protected device roster, and every device
keeps its own secret key, MLS leaves, ratchets, inbox, and durable store.
Devices never share encryption state, and the relay never sees the roster or
which devices belong to which account — roster updates travel only inside
existing encrypted sessions.

Linking follows the Signal shape, and only one small payload ever travels out
of band. The new device produces short-lived request bytes (about 750 bytes —
comfortably one QR code or deep link); an existing device verifies user
intent, signs the next roster revision, and publishes the encrypted response
envelope straight to the new device's relay inbox. The envelope is sealed to
the request's ephemeral key, so the relay carries only opaque bytes with a
five-minute lifetime:

```ts
// On the new device: create a five-minute link request and keep syncing.
const request = await newDevice.linkDevice(); // render as a QR code

// On an existing device: verify intent and authorize. The encrypted
// envelope is delivered through the relay automatically.
await existingDevice.authorizeDevice(request);

// The new device completes the link on its next synchronization —
// no second scan and no manual transport.
```

`authorizeDevice` also returns the envelope bytes, and `completeDeviceLink`
accepts them directly, for applications that link devices without any relay
connectivity. The envelope grows with the roster, so it is not guaranteed to
fit in a QR code — use a network channel for manual transport.

From that point everything is automatic. Murmur drives MLS Adds and Welcomes
for the new device in every known contact and service session, and MLS
Removes after a revocation, without any application involvement. Application
code keeps seeing accounts: `session.members` and `update.sender` are stable
account keys, not device keys, so a messenger built on Murmur needs no
device-awareness at all.

```ts
// Any active device may inspect and control the roster.
const devices = await murmur.devices(); // roster entries with status
await murmur.revokeDevice(otherDeviceKey); // stops delivery and drives MLS Removes

// Lifecycle callbacks in the same sync loop:
await murmur.sync({
    onDeviceAdded: (events) => console.log("own device added", events),
    onDeviceRevoked: (events) => console.log("own device revoked", events),
    onContactRosterChanged: (events) => console.log("contact devices changed", events),
});
```

Peers learn about additions and revocations only from the authenticated,
account-signed roster carried over their existing sessions, never from an
unauthenticated server claim. Losing a device store still loses that device's
state: a replacement links as a fresh device and receives new Welcomes;
application history transfer stays application-owned.

The repository also contains internal, deliberately unexported groundwork for
private group state — Ristretto255 credential mathematics, encrypted member
identifiers, and an opaque group-state service that cannot read its members
(`packages/murmur/sources/math`, `privateGroups`, `privateGroupState`). It
requires external cryptographic audit before any production exposure.

## Typed synchronization services

Services are how applications build domains — chat, documents, files — on top
of sessions. A service is an object with exactly two protocol entry points:

```ts
interface MurmurService {
    /** Return true to durably claim a newly observed session. */
    onNewSession(descriptor: MurmurServiceSessionDescriptor): boolean | Promise<boolean>;
    /** Receive every later update for sessions this service owns. */
    onUpdate(update: MurmurUpdate): void | Promise<void>;
}
```

Register services with stable IDs at open time (or later with
`registerService`); IDs must be unique because they are the durable routing
key:

```ts
const notesService = {
    onNewSession: async (session) => new TextDecoder().decode(session.descriptor) === "notes/v1",
    onUpdate: async (update) => {
        // update.id (stable), update.sessionId, update.sender, update.bytes
        await applyNotePacket(update.id, update.bytes);
    },
};

const murmur = await MurmurClient.open({
    relay: "https://relay.example",
    store,
    services: [{ id: "notes", service: notesService }],
});
```

When a new session arrives, registered services are offered its descriptor in
service-ID order. The first `true` claims it: Murmur persists the
session-to-service mapping, activates the session, and from then on routes its
updates only to that service's `onUpdate`. Locally created sessions can be
assigned an owner up front with `createSession({ ..., service: "notes" })`.
Services are independent; Murmur models no dependencies between services or
sessions, and future chat is simply another service.

Service-owned sessions use the ordinary session API — `send`, membership
intents, and role policy controls — so a service can run two-person and group
sessions alike:

```ts
const notesSession = await murmur.createSession({
    descriptor: new TextEncoder().encode("notes/v1"),
    contacts: [bobIdentity, carolIdentity],
    service: "notes",
});
await murmur.send(notesSession.id, encodeNotePacket({ type: "insert", text: "hi" }));
```

Murmur provides no service storage. A custom service owns application state
through whatever persistence its application chooses; `MurmurStore` remains
private to the engine and built-in Murmur domains. Murmur durably stores only
the session-to-service routing association.

`unregisterService(id)` removes the handler without touching Murmur's durable
owner mappings. It is not a pause mechanism: updates arriving for that
service's already-owned sessions are acknowledged and discarded while the
handler is absent, and registering it again does not replay them. Unregister
only when that loss is intentional.

## The synchronization loop

One identity-wide loop drives everything: it maintains the recipient-
authenticated SSE connection, publishes durable outboxes, processes the inbox
in UUIDv7 order, and fans batches out to contact handling, service handlers,
and the optional global callbacks.

```ts
const abort = new AbortController();

const running = murmur.sync({
    abort: abort.signal,
    onConnected: () => console.log("SSE connected"),
    onDisconnected: (error) => console.log("SSE dropped", error),
    onUpdates: async (updates) => {
        for (const update of updates) {
            // A service-owned update already ran through that service's
            // onUpdate. Handle only ownerless application updates here.
            if (update.service !== undefined) continue;
            await applyToApplicationState(update);
        }
    },
    onContactRequested: async (requests) => {
        /* ... */
    },
    onContactAdded: async (contacts) => {
        /* ... */
    },
    onContactUpdated: async (contacts) => {
        /* ... */
    },
    onContactRemoved: async (contacts) => {
        /* ... */
    },
});
```

What the loop guarantees:

- **The stream carries real data.** SSE delivers each exact queued encrypted
  delivery with its relay UUIDv7 event ID — it is not a wake-only channel.
  Ordering is guaranteed within one identity's inbox, never across identities.
- **Acknowledgement follows durability.** A relay item is acknowledged only
  after its processing outcome — new MLS state, replay and queue progress, and
  any buffered application update — is atomically persisted. A crash before
  that simply causes harmless redelivery.
- **Callbacks gate the local batch.** Murmur runs every relevant service
  handler and callback for a batch, and commits and drains that batch only
  after they all resolve. A thrown handler or a crash re-delivers the same
  batch with the same stable event IDs after restart.
- **Outbound work wakes the loop.** `send`, `createSession`, membership
  changes, profile refreshes, and contact actions persist durable outboxes and
  signal the running loop, which publishes them and retries transient relay
  failures with backoff.
- **Reconnection is automatic.** On a dropped or transiently failing
  connection the loop calls `onDisconnected`, waits briefly, reconnects from
  the durable cursor, and calls `onConnected` again. Non-transient errors
  (other than network failures, HTTP 429, and 5xx) end the loop with a thrown
  error.

All options are optional. Contacts and registered services keep flowing even
without a global `onUpdates`; updates for sessions with no owner stay durably
buffered until an `onUpdates` hook exists to receive them. Aborting the signal
ends the loop; `await` the returned promise to know it has fully stopped.

Install services and lifecycle callbacks before starting synchronization.
Service-owned updates are intentionally also visible in global `onUpdates`
with `update.service` set; do not apply them a second time there. If a contact
lifecycle callback is omitted, its durable contact state is still queryable
through `contacts()` or `contactRequests()`, but that lifecycle event is not
replayed when a callback is registered later.

`synchronize(options?, callbacks?)` is the bounded foreground alternative: one
publish-and-drain cycle with an optional long-poll (`waitMilliseconds`) that
returns an observable `MurmurSynchronizeResult`. It cannot run while `sync()`
is active.

## Durability, offline use, and idempotency

Murmur is offline-first. Opening a client restores identity, contacts,
sessions, and service routing from the store before any relay contact, so
Murmur reads and mutations work immediately. Sends and membership changes made
offline persist as durable outboxes and publish when connectivity returns.
Unacknowledged inbound deliveries wait in the relay queue within its quota and
TTL — the queue bound defines the maximum supported offline window, not an
archive.

Delivery to the application is _at-least-once with stable IDs_. Murmur
deduplicates protocol-level redelivery internally, but an application callback
that ran without its batch committing (a throw, a crash, a power cut) will see
the same updates again. Custom-service effects live outside `MurmurStore`, so
deduplicate them using the stable `update.id`. The same applies to contact
lifecycle events and service `onUpdate` calls: each carries a stable `id`
precisely so replays are cheap to detect.

## Graceful shutdown

Stop the loop, wait for it, then close:

```ts
const abort = new AbortController();
const running = murmur.sync({ abort: abort.signal, onUpdates });

process.on("SIGTERM", async () => {
    abort.abort(); // ends the SSE loop at a safe point
    await running; // wait for in-flight batch handling to finish
    murmur.close(); // zeroes in-memory identity secrets
});
```

`close()` destroys in-memory secret material only — all durable state remains
in the application's store, ready for the next `open()`. It throws if called
while operations are still pending, which is a signal to abort and await the
sync loop first. Because every acknowledgement follows durable persistence, a
hard kill at any point is safe: the next start resumes from the durable
cursor, republishes pending outboxes, and re-offers any uncommitted batch.

## Security and trust model

- **End-to-end encryption.** Session traffic is MLS-protected with forward
  secrecy and post-compromise security through TreeKEM epochs. The relay
  stores and forwards ciphertext it cannot read, and cached discovery bundles
  contain only public, signed material.
- **Authenticated queues.** Publishing is sender-signed and reading or
  acknowledging a queue requires signatures from the recipient identity. The
  relay cannot forge a valid delivery or recipient acknowledgement, though an
  untrusted relay can still delay or drop traffic.
- **Metadata is not hidden.** The relay learns authenticated sender and
  recipient identities, exact multicast fanout, timing, sizes, and queue
  progress. Murmur promises encrypted contents, not anonymous routing; if you
  need metadata privacy, Murmur is the wrong layer for it.
- **Invitations are bearer capabilities.** A digest or bundle lets anyone who
  holds it _attempt_ a bootstrap. Acceptance always remains with the
  recipient: contact requests need an explicit accept, ownerless sessions may
  require explicit activation, and pending state is strictly bounded against
  flooding.
- **Revocation is owner-authorized but relay-dependent.** Invitation digests
  contain no revocation secret. A failed offline revocation destroys local
  one-use keys but cannot remove a remote cache row until retry; an established
  session is outside invitation revocation.
- **Offline contact admission is an availability tradeoff.** Contacts normally
  use one-use KeyPackages, but retain one reusable last-resort package so group
  creation cannot be blocked by an offline peer. Compromise of that retained
  fallback can expose captured Welcomes encrypted to it; refill rotates it when
  the contact reconnects.
- **No recovery from the relay.** Acknowledged deliveries are deleted; the
  relay is never history. A lost store means lost sessions — plan real
  backups of the application store.
- **One store per device.** Each linked device owns its own store and inbox.
  Running two live clients against one device's queue splits the cursor and
  corrupts delivery; link a second device instead of sharing stores or roots
  between concurrent processes.
- **Device authorization is roster-signed.** Adding or revoking a device is an
  account-signed, replay-protected roster mutation distributed over existing
  encrypted sessions; the relay cannot forge, reorder, or hide one from peers
  that share a session with the account.
- **Operational hygiene.** Keys are `Uint8Array`s that Murmur zeroes when
  finished (`close()` zeroes the identity); never log them. Public identities
  are free to create, so a production relay deployment needs its own
  non-Sybil admission control in front of ingress.

Murmur is a `0.x` project and has not received an independent security audit.

## Running a relay locally

The relay is a small Node service (Node 22.5+) with SQLite and Postgres
backends. From this repository:

```bash
pnpm install
pnpm --filter @slopus/murmur-relay build
MURMUR_RELAY_STORE=sqlite \
MURMUR_RELAY_DB=./data/murmur-relay.sqlite \
MURMUR_RELAY_ORIGINS='http://localhost:5173' \
pnpm --filter @slopus/murmur-relay start
```

Point `MurmurClient.open({ relay: "http://127.0.0.1:8787", ... })` at it and
the whole walkthrough above runs locally. Set `MURMUR_RELAY_STORE=postgres`
with a Postgres URL in `MURMUR_RELAY_DB` for the Postgres backend.

The standalone process speaks plain HTTP and is meant for local development.
Production deployments require TLS termination and an admission boundary that
authenticates non-Sybil principals — see the
[relay README](https://github.com/slopus/murmur/blob/main/packages/murmur-relay/README.md)
and [deployment notes](https://github.com/slopus/murmur/blob/main/docs/DEPLOYMENT.md)
for quotas, environment variables, and operational logging.

## Development

```bash
pnpm install
pnpm format       # oxfmt --write .
pnpm lint         # oxlint
pnpm typecheck
pnpm test         # vitest across the workspace, real stores and a real relay
pnpm build
```

Deeper reference material lives in the repository docs:
[architecture](https://github.com/slopus/murmur/blob/main/docs/ARCHITECTURE.md),
[protocol](https://github.com/slopus/murmur/blob/main/docs/PROTOCOL.md),
[relay API](https://github.com/slopus/murmur/blob/main/docs/RELAY_API.md), and
[security notes](https://github.com/slopus/murmur/blob/main/docs/SECURITY.md).

## Protocol versions

Murmur v0.4 uses contact protocol and contact storage version 2. It is a clean
break from the v0.3 contact format. Relay schema v4 adds owner-authorized
invitation metadata and expiring revocation tombstones. SQLite and Postgres
migrate schema v3 in place without deleting pending deliveries or invitations.
