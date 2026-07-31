# Security

> Murmur is a `0.x` project. **It has not received an independent security
> audit.** The MLS implementation is a tested Murmur profile of RFC 9420, not a
> complete general-purpose implementation. Do not rely on it for
> life-safety-critical confidentiality.

## Threat model

### Assumed hostile

- **The relay.** It may read everything it stores, drop, delay, reorder, or
  duplicate messages, and lie about what it has. It cannot read plaintext or
  forge membership.
- **The network.** Assumed fully observed and modifiable. TLS is defence in
  depth, not the security boundary — every envelope is independently signed.
- **Other users.** A group member cannot forge messages or document edits
  attributed to another member.

### Assumed trusted

- **The local device**, its RAM, and the `MurmurStore` backing it. Murmur has no
  defence against a compromised endpoint.
- **The out-of-band channel** used to exchange identity tokens. See
  [Key exchange](#key-exchange-is-the-weak-point).

## What is guaranteed

| Property                       | Mechanism                                               |
| ------------------------------ | ------------------------------------------------------- |
| Confidentiality from the relay | All payloads encrypted client-side                      |
| Sender authenticity            | Ed25519 over a canonical payload                        |
| Recipient binding              | Signature and AEAD associated data cover the recipient  |
| Replay resistance (messages)   | Store-transactional replay markers                      |
| Replay resistance (queue ops)  | Single-use `requestId`, ±5-minute validity              |
| Exactly-once acceptance        | Application record and replay marker in one transaction |
| Group forward secrecy          | MLS epochs; a removed member cannot read later traffic  |
| Membership integrity           | Enforced by TreeKEM, not by the relay                   |
| File integrity                 | Content-addressed blobs, AEAD-bound metadata            |
| Document authorship            | Operation actor bound to the authenticated MLS leaf     |

## What is not protected

### Metadata

The relay sees, and can retain indefinitely:

- Topic identifiers — opaque hashes, but **stable and linkable over time**
- Sender public keys on every envelope, since it verifies signatures
- Explicit recipient identifiers
- Message and blob sizes, and precise timing
- Which identities subscribe to which topics

This is enough to reconstruct a social graph and communication patterns. Murmur
protects _content_, not _who talks to whom_. There is no cover traffic, no
padding by default, and no mixing. If metadata resistance matters, run your own
relay or use a different system.

`prepareSend` accepts a padding argument for MLS application messages, which
blunts size correlation but does not remove it.

### Key exchange is the weak point

Identity tokens are exchanged out of band, and **Murmur does not verify them**.
An attacker who controls that channel can substitute their own token and mount a
classic machine-in-the-middle attack. Everything downstream is then correctly
encrypted to the wrong party.

There is no safety-number comparison, no key-transparency log, and no trust-on-
first-use warning on key change. Verify tokens over a channel you trust
independently.

### Compromise

- **No post-compromise security for direct messages.** They use sealed boxes to
  a long-term X25519 key, not a Double Ratchet. An attacker who steals a private
  encryption key can decrypt all past _and future_ direct messages to that
  identity. Groups do better: MLS epochs give forward secrecy across membership
  changes.
- **No secure deletion.** `zeroBytes` clears buffers, but the runtime may have
  copied them, and durable state is only as protected as the underlying store.
- **No key rotation.** An identity's keys are fixed for its lifetime; rotation
  means a new identity.

### Availability

Relays promise nothing. A malicious relay can withhold messages indefinitely,
and clients cannot distinguish that from a quiet peer. Publishing to multiple
relays mitigates this.

## Operator exposure

Running a public relay means accepting writes from anyone, because keypairs are
free. The relay has **no quota system**. Without rate limiting, a public relay
can be filled at will. See
[DEPLOYMENT.md](DEPLOYMENT.md#running-a-public-relay).

Blob reads are unauthenticated: possession of the content hash is the
capability. The bytes are useless without the descriptor from the message that
referenced them, but a hash leak means the ciphertext is fetchable.

## Implementation practices

- All key material is `Uint8Array`; base64url only at boundaries.
- Secrets are zeroed with `zeroBytes` on the failure path as well as success.
- Constant-time comparison for authentication tags.
- Every input is validated and size-bounded before any cryptographic operation.
- Cryptographic failures **throw**; there are no null returns to ignore.
- Only `@noble/*` primitives — no hand-rolled cryptography.
- Sizes are bounded at every layer to limit memory-exhaustion attacks.

## Reporting

Report suspected vulnerabilities privately to the maintainer rather than opening
a public issue.
