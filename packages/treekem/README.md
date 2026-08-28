# `@slopus/treekem`

Small, stateless TreeKEM group key agreement for browsers and Node.js. The
package keeps no hidden state: every operation consumes an opaque byte array
and returns its replacement.

```ts
import * as treekem from "@slopus/treekem";

const equal = (left: Uint8Array, right: Uint8Array): boolean =>
    left.length === right.length && left.every((byte, index) => byte === right[index]);

const alice = treekem.keyPair();
const bob = treekem.keyPair();

const initial = treekem.create(alice);
const added = treekem.update(initial.secretState, { add: [bob.publicKey] });
const joined = treekem.join(bob.secretKey, added.publicWelcomes[0]!);

// Both sides received the same fresh secret.
console.assert(equal(added.secretKey, joined.secretKey));

const bobUpdate = treekem.update(joined.secretState);
const aliceUpdate = treekem.apply(added.secretState, bobUpdate.publicPacket);
console.assert(equal(bobUpdate.secretKey, aliceUpdate.secretKey));

treekem.destroy(initial.secretState, initial.secretKey, bob.secretKey);
```

The application must authenticate a member's public admission key before
adding it. Ongoing update packets are signed and verified by the package. Any
current member can add or remove another member; authorization policy belongs
to the embedding protocol.

`join()` verifies that a Welcome was signed by a member of the enclosed tree,
but it cannot establish who that group represents. Call it only after the
embedding protocol authenticates the Welcome's sender or exact bytes; an
untrusted server must not be the recipient's source of inviter identity.

## Public and private bytes

An untrusted public server may persist and deliver only the public artifacts:

| Value                       | Server storage      | Contents                                       |
| --------------------------- | ------------------- | ---------------------------------------------- |
| `keyPair().publicKey`       | Yes                 | Public admission material                      |
| `update().publicPacket`     | Yes                 | Signed update with HPKE-encrypted path secrets |
| `update().publicWelcomes[]` | Yes, until consumed | Recipient-encrypted joining state              |
| `keyPair().secretKey`       | Never               | One-use admission secret                       |
| `secretState`               | Never               | Local signing key and private TreeKEM path     |
| `secretKey`                 | Never               | Shared epoch secret                            |

The server treats packets and Welcomes as exact opaque bytes. Delete a Welcome
after its recipient consumes it: later compromise of that admission secret
could decrypt a retained historical Welcome. Update packets may be retained if
the embedding protocol accepts their visible group-size, leaf-index, and key
metadata.

There is deliberately no public tree snapshot export. Delivery servers need
only packets and Welcomes; a public tree alone cannot recover a member's lost
private path.

Persist the newest returned state before discarding the previous state. Never
reuse or roll state back. Call `destroy()` on replaced state, consumed secret
keys, and shared secrets when their lifetime ends.

The implementation follows the RFC 9420 TreeKEM shape—left-balanced node
indices, direct paths, copath resolutions, unmerged leaves, path-secret
derivation, and HPKE path delivery—but deliberately uses its own small,
versioned wire format. It is not an MLS wire implementation.

## API

- `keyPair(): TreeKemKeyPair` creates a one-use admission key pair.
- `create(keyPair): TreeKemResult` creates a one-member group.
- `update(secretState, changes?): TreeKemUpdateResult` refreshes the sender path
  and atomically adds or removes zero or more members. Removals happen before
  additions, and `publicWelcomes` follows the order of `changes.add`.
- `apply(secretState, publicPacket): TreeKemResult` authenticates and applies an
  update.
- `join(secretKey, publicWelcome): TreeKemResult` enters a group from a Welcome.
- `destroy(...values): void` overwrites caller-owned secret byte arrays.

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
