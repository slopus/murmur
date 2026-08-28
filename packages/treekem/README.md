# `@slopus/treekem`

Small, stateless TreeKEM group key agreement for browsers and Node.js. Every
member sees the same three-field group shape. The package keeps no hidden state:
each operation consumes opaque private state and returns its replacement.

```ts
import * as treekem from "@slopus/treekem";

const alice = treekem.keyPair();
const bob = treekem.keyPair();

const created = treekem.create(alice);

const added = treekem.update(created.secretState, {
    add: [bob.publicKey],
});

const joined = treekem.join(bob.secretKey, added.publicWelcome[bob.publicKey]!);

const rotated = treekem.update(joined.secretState);

const applied = treekem.apply(added.group.secretState, rotated.publicGroupMessage);

// rotated.group and applied now have the same secretKey and members.
```

Every local group has exactly this shape:

```ts
interface TreeKemKeyPair {
    readonly publicKey: string;
    readonly secretKey: string;
}

interface TreeKemGroup {
    readonly secretState: Uint8Array;
    readonly secretKey: Uint8Array;
    readonly members: readonly string[];
}
```

`secretState` is different for every member. `secretKey` and `members` converge
after everyone consumes the same update. Members are represented by their
stable admission public keys in tree-leaf order.

Admission public and secret keys are canonical base64url strings, as are the
public keys in `members`. The group `secretKey`, opaque `secretState`, and public
messages are byte arrays.

Persist `secretState`; it is the private source of truth for the member's current
TreeKEM position and group secret. The package loads the binary `secretKey` from
that state and returns it for immediate cryptographic use. Applications do not
need to persist `secretKey` separately.

`update()` additionally returns one opaque `publicGroupMessage` for all existing
members and a recipient-keyed `publicWelcome` object for newly added members:

```ts
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

| Value                         | Server storage      | Contents                                   |
| ----------------------------- | ------------------- | ------------------------------------------ |
| `keyPair().publicKey`         | Yes                 | Public admission material                  |
| `group.members`               | Yes                 | Current stable member public keys          |
| `update().publicGroupMessage` | Yes, until consumed | Signed update for existing members         |
| `update().publicWelcome[key]` | Yes, until consumed | Recipient-encrypted joining state          |
| `keyPair().secretKey`         | Never               | One-use admission secret                   |
| `group.secretState`           | Never               | Local signing key and private TreeKEM path |
| `group.secretKey`             | Never               | Shared epoch secret                        |

The server treats every message as exact opaque bytes. Delete each Welcome after
its intended recipient consumes it: later compromise of an admission secret
could decrypt retained historical joining data. The server can observe update
timing, size, group identifiers, leaf indices, and public membership changes.

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
- `create(keyPair): TreeKemGroup` creates a group containing only the creator.
- `update(secretState, changes?): TreeKemUpdateResult` refreshes the sender path
  and atomically adds or removes zero or more members. Removals happen before
  additions. It returns the replacement local `group`, one
  `publicGroupMessage`, and recipient-keyed `publicWelcome` entries.
- `apply(secretState, publicGroupMessage): TreeKemGroup` applies an update for
  an existing member.
- `join(secretKey, publicWelcome): TreeKemGroup` decrypts one member's unique
  joining state.
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
