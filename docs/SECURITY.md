# Security

Murmur treats the relay as untrusted ordered storage. The relay sees topic
descriptors, outer author keys, timing, sizes, expiration, and sequence
activity. It does not receive topic secrets, identity secrets, profiles,
friend-control plaintext, group descriptors, MLS application bytes, Welcome
plaintext, epoch secrets, MLS PublicMessage headers, or Murmur identity
credentials carried by Commits. Both Commit and application MLS messages are
hidden in the same outer group ciphertext.

Murmur has not received an independent security audit. The MLS implementation
is a tested Murmur profile and RFC 9420 subset, not a claim of complete
interoperability or a substitute for an audit.

## Guarantees

- Friend request and response contents are recipient-confidential,
  identity-authenticated, and outer-author unlinkable.
- Friend control content is pairwise encrypted with distinct directional keys
  and identity-signed.
- Group membership changes are real TreeKEM Commits.
- Group relay payloads use a strict versioned AEAD key domain derived from the
  stable random topic secret, with a random nonce and AAD binding the envelope
  domain and complete topic. The Ed25519 capability secret is not reused
  directly as an encryption key.
- The relay cannot classify group Commit and application payloads or decode
  their MLS headers.
- Removed members cannot authenticate or decrypt later inner MLS application
  events.
- Every outbound relay event is stored exactly before network access.
- Ambiguous publication retries the same bytes, ID, author, and signature.
- MLS ratchets never advance only in RAM: cloned post-state and the exact event
  commit atomically.
- Relay order, not publish return order, chooses concurrent Commit winners.
- Invalid, tampered, and wrong-topic-secret retained events cannot permanently
  stall a topic.
- Awaited `close()` and `destroy()` abort convergence, await serialized active
  work, then zero live identity, topic, and epoch secrets.

## Signed event age is not replay protection

A valid event that was never accepted remains publishable regardless of how old
its `createdAt` is. This is deliberate: offline durable outboxes and clients
whose clocks are behind the relay must not lose signed work merely because time
passed before connectivity returned.

The relay still rejects timestamps more than five minutes in its future and
rejects an `expiresAt` deadline that has elapsed. Durable `(topic, id)` receipts
provide idempotency for accepted content and collision detection for changed
authenticated content. Applications that need a business-level freshness limit
must encode and authenticate that policy inside the opaque payload; relay event
age is not a revocation or anti-replay boundary.

## Collapse is arrival-ordered

The relay applies collapse when it accepts a publication. It does not compare
`createdAt` or inspect an application version, so a delayed publication
carrying older logical state can arrive later and delete newer retained state
from the same author and collapse key.

Applications using collapse must include an authenticated logical version in
the opaque payload and reject regressions when applying events. This ordering
belongs above the untrusted relay boundary: letting the relay interpret an
application version would give it message semantics and would not make a
malicious relay trustworthy.

## Relay and storage limits

- A relay can deny service by refusing, deleting, delaying, or replaying
  ciphertext. Cryptography does not guarantee delivery or availability.
- Only events carrying an explicit `expiresAt` are omitted and eligible for
  pruning after that deadline. Events without `expiresAt` are not age-pruned;
  topic heads and idempotency receipts are durable, and the current relay does
  not age-prune topics or receipts.
- Collapse can delete older retained events from the same topic, author signing
  key, and collapse key. It leaves stable sequence holes and does not remove the
  corresponding durable idempotency receipts.
- A current group member can read and write current group content.
- Removed members retain the stable relay capability and topic secret, so they
  can decrypt the outer envelope and inject junk. They lack newer MLS epoch
  secrets and therefore cannot decrypt or authenticate valid newer-epoch inner
  content.

## Limits

- Public identity keys still need an authenticated out-of-band exchange.
- Compromise of the single identity root gives both Ed25519 signing and the
  converted X25519 key-agreement capability; they are intentionally one
  recovery and compromise domain.
- The public identity inbox is intentionally linkable to that identity.
- Invitation verification proves exact retained Commit/Welcome consistency,
  but a malicious inviter can name its losing fork. Joining therefore trusts an
  honest inviter/current group member; relay order is not a membership-validity
  oracle for the joiner.
- Local storage compromise exposes the identity, friend capabilities,
  KeyPackage bundles, and MLS checkpoints held there.
- The relay can observe and correlate topic IDs, outer event author keys,
  timing, sizes, expiration, collapse-key equality, and sequence activity.
- The relay can deny service, withhold, reorder, or delete retained data.
- This implementation has not received an independent cryptographic audit.
