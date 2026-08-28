# `@slopus/treekem`

Small, stateless TreeKEM group key agreement for browsers and Node.js. Every
member sees the same group view. The package keeps no hidden state:
each operation consumes opaque private state and returns its replacement.

## Requirements

- Provide a simple NaCl-style API that abstracts away TreeKEM, group encryption,
  and membership mechanics.
- Assume an honest-but-untrusted public server, or another external coordinator,
  facilitates epochs by authenticating, serializing, persisting, and delivering
  public group transitions.
- Expose the member list to that public facilitator so it can enforce complete
  delivery, reject stale or unauthorized group changes, and require a fresh
  re-key before accepting further activity. The facilitator cannot perform the
  re-key itself and never receives group secrets.

```ts
import * as treekem from "@slopus/treekem";

const alice = treekem.keyPair();
const bob = treekem.keyPair();

const created = treekem.create(alice);

const added = treekem.update(created.group.secretState, {
    add: [bob.publicKey],
});

const joined = treekem.join(bob.secretKey, added.publicWelcome[bob.publicKey]!);

const rotated = treekem.update(joined.secretState);

const applied = treekem.apply(added.group.secretState, rotated.publicGroupMessage);

// rotated.group and applied have the same secretKey, members, and epoch.
```

Every local group has this shape:

```ts
interface TreeKemKeyPair {
    readonly publicKey: string;
    readonly secretKey: string;
}

interface TreeKemGroup {
    readonly secretState: Uint8Array;
    readonly secretKey: Uint8Array;
    readonly members: readonly string[];
    readonly epoch: string;
}
```

`secretState` is different for every member. `secretKey`, `members`, and `epoch`
converge after everyone consumes the same update. Members are represented by
their stable admission public keys in tree-leaf order.

Admission public and secret keys are canonical base64url strings, as are the
public keys in `members`. The group `secretKey`, opaque `secretState`, and public
messages are byte arrays.

Persist `secretState`; it is the private source of truth for the member's current
TreeKEM position and group secret. The package loads the binary `secretKey` from
that state and returns it for immediate cryptographic use. Applications do not
need to persist `secretKey` separately.

`create()` returns the creator's private group and an initial signed
`publicGroupMessage`. `update()` returns the replacement private group, a new
`publicGroupMessage` for all existing members, and a recipient-keyed
`publicWelcome` object for newly added members:

```ts
interface TreeKemCreateResult {
    readonly group: TreeKemGroup;
    readonly publicGroupMessage: Uint8Array;
}

interface TreeKemUpdateResult {
    readonly group: TreeKemGroup;
    readonly publicGroupMessage: Uint8Array;
    readonly publicWelcome: Readonly<Record<string, Uint8Array>>;
}
```

Existing members consume `publicGroupMessage` with `apply()`. Every added member
has a unique Welcome encrypted to its admission public key and consumes only
`publicWelcome[publicKey]` with `join()`. A Welcome contains the public group
state needed to join, so joining never requires both messages.

## Public group state

`publicGroupMessage` is an authenticated public membership transition. A server
applies it without receiving any group secrets:

```ts
const publicCreated = treekem.applyPublic(undefined, created.publicGroupMessage);

const publicAdded = treekem.applyPublic(
    publicCreated.publicState,
    added.publicGroupMessage,
    added.publicWelcome,
);
```

```ts
interface TreeKemPublicGroup {
    readonly publicState: Uint8Array;
    readonly members: readonly string[];
    readonly epoch: string;
}
```

`publicState` contains the group identifier, epoch, public tree, and the keys
needed to authenticate the next transition. It contains no path secrets or
group secret. The server persists the newest `publicState`; `members` and
`epoch` are views loaded from it and do not need separate persistence.

`applyPublic()` verifies that the message's parent epoch equals the supplied
public state's current epoch and that the message was signed by a current
member. When additions are present, it also verifies that `publicWelcome`
contains exactly one Welcome for every added public key. The embedding server
still decides who may change membership and checks that delivery recipients
cover every required member.

The initial public message is self-signed by the creator. The embedding server
must authenticate and authorize that creator before registering the group.

## Epochs

An epoch is a canonical UUIDv7 string identifying one exact group state.
`create()` generates the initial epoch. Every `update()` names its current epoch
as `parentEpoch` inside the signed `publicGroupMessage` and generates a fresh
UUIDv7 as the resulting epoch. `join()`, `apply()`, and `applyPublic()` expose
that resulting epoch.

The epoch is an opaque version identifier. Its embedded timestamp is useful for
operations and indexing, but it never decides which concurrent update wins and
clients must not compare UUID values to resolve conflicts.

Group transitions are serialized with an atomic compare-and-swap. The server
accepts a `publicGroupMessage` only when its signed `parentEpoch` exactly equals
`publicGroup.epoch`. The accepted message replaces `publicState` and its new
UUID becomes the current epoch. Every competing message built from the previous
epoch is stale and rejected, regardless of its UUID timestamp or lexical order.

The sender keeps its previously accepted `secretState` until its update is
accepted. After rejection it destroys the tentative returned group, applies the
accepted competing transition to the old state, and recreates its desired
change from the new epoch.

Application-message envelopes should carry the UUID epoch they encrypted for.
The server can reject a new publication whose epoch differs from the current
public group, while already accepted deliveries retain their established queue
order.

The application must authenticate a member's public admission key before
adding it. Ongoing updates are signed and verified by the package. Any current
member can add or remove another member; authorization policy belongs to the
embedding protocol.

`join()` verifies that the joining data was signed by a member of the enclosed
tree, but it cannot establish who that group represents. Call it only after the
embedding protocol authenticates the message's sender or exact bytes; an
untrusted server must not be the recipient's source of inviter identity.

## Public and private bytes

An untrusted public server may persist and deliver only the public values:

| Value                         | Server storage      | Contents                                      |
| ----------------------------- | ------------------- | --------------------------------------------- |
| `keyPair().publicKey`         | Yes                 | Public admission material                     |
| `publicGroup.publicState`     | Yes                 | Public tree and transition-verification state |
| `publicGroup.members`         | Derived             | Current stable member public keys             |
| `publicGroup.epoch`           | Derived             | Current UUIDv7 group version                  |
| `create().publicGroupMessage` | Yes, until applied  | Signed initial public group                   |
| `update().publicGroupMessage` | Yes, until applied  | Signed membership and tree transition         |
| `update().publicWelcome[key]` | Yes, until consumed | Recipient-encrypted joining state             |
| `keyPair().secretKey`         | Never               | One-use admission secret                      |
| `group.secretState`           | Never               | Local signing key and private TreeKEM path    |
| `group.secretKey`             | Never               | Shared epoch secret                           |

The server handles exact message bytes through `applyPublic()` rather than
decoding the wire format itself. Delete each Welcome after its intended
recipient consumes it: later compromise of an admission secret could decrypt
retained historical joining data. The server can observe update timing, size,
group identifiers, epochs, leaf indices, and public membership changes.

There is deliberately no public-tree API. A public tree alone cannot recover a
member's lost private path.

Persist the newest returned `secretState` before discarding the previous state.
Never reuse or roll state back. Call `destroy()` on replaced state and loaded
group secrets when their lifetime ends.

The implementation follows the RFC 9420 TreeKEM shape—left-balanced node
indices, direct paths, copath resolutions, unmerged leaves, path-secret
derivation, and HPKE path delivery—but deliberately uses its own small,
versioned wire format. It is not an MLS wire implementation.

## API

- `keyPair(): TreeKemKeyPair` creates a one-use string admission key pair.
- `create(keyPair): TreeKemCreateResult` creates a group containing only the
  creator and its initial public group message.
- `update(secretState, changes?): TreeKemUpdateResult` refreshes the sender path
  and atomically adds or removes zero or more members. Removals happen before
  additions. It returns the replacement local `group`, one
  `publicGroupMessage`, and recipient-keyed `publicWelcome` entries.
- `apply(secretState, publicGroupMessage): TreeKemGroup` applies an update for
  an existing member.
- `join(secretKey, publicWelcome): TreeKemGroup` decrypts one member's unique
  joining state.
- `applyPublic(publicState, publicGroupMessage, publicWelcome?): TreeKemPublicGroup`
  verifies a public transition and returns replacement server state, membership,
  and epoch. Pass `undefined` as `publicState` only for group creation.
- `destroy(...values): void` overwrites caller-owned secret-state and group-key
  byte arrays. Admission secret keys are strings; JavaScript strings are
  immutable and cannot be zeroed.

All byte arrays returned by the package are independently owned by the caller.
Input arrays are never modified.

## Security profile

- RFC 9180 DHKEM(X25519, HKDF-SHA-256) HPKE base mode
- AES-128-GCM HPKE payload protection
- SHA-256 TreeKEM derivation and tree hashes
- Ed25519 update and Welcome signatures
- Fresh path randomness on every update

There is no transport, persistence, application-message cipher, account model,
role policy, or delivery ordering in this package.
