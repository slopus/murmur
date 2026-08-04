# Security

Murmur encrypts application content on clients and treats relays as untrusted
storage and routing infrastructure. This document states the current
guarantees and, just as importantly, what is not protected.

Murmur has not received an independent security audit. The MLS implementation
is a tested Murmur profile and RFC 9420 subset, not a claim of complete
interoperability or a substitute for an audit.

## Threat model

Murmur assumes that a relay, network observer, or storage operator may:

- read all relay database rows and ciphertext blobs;
- observe topic IDs, outer event author signing keys, event timing, and sizes;
- delay, drop, reorder, duplicate, or delete responses and stored data;
- return malformed state, stale state, or arbitrary ciphertext;
- attempt invalid event writes and blob uploads;
- operate multiple relay instances with independent in-memory rate-limit state.

The protocol verifies cryptographic input before using it as application data,
but cannot make a malicious relay available or hide the metadata it must see.

Murmur also considers a local key compromise and a substituted public identity
token to be serious threats. They are not magically repaired by relay
encryption.

## Guarantees

| Property                                        | What the implementation guarantees                                                                                                   | Conditions and limits                                                                                                        |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------- |
| Identity-key separation                         | Ed25519 signs; X25519 receives sealed boxes.                                                                                         | Compromising one key type does not by itself give the other capability.                                                      |
| Contact-profile authenticity                    | A decrypted profile is signed by the identity it claims and bound to its intended recipient.                                         | Only meaningful if the recipient already has the genuine sender public token.                                                |
| First-contact privacy                           | An identity inbox exposes a count of unlinkable outer requests rather than a stable sender author.                                   | The inbox is readable by anyone who knows the recipient token; only `publishUnlinkable()` provides this outer unlinkability. |
| Pairwise-topic privacy                          | Public identity tokens alone cannot derive a direct conversation topic.                                                              | Both parties need X25519 secret material. Possession of the topic remains read capability.                                   |
| Direct-message confidentiality and authenticity | Direct message contents are signed by the sender and sealed to the recipient's X25519 key.                                           | Does not provide post-compromise security; see below.                                                                        |
| File confidentiality and integrity              | Files are AES-GCM encrypted before upload; the descriptor is encrypted with the message; blob IDs verify SHA-256 ciphertext content. | Anyone with the descriptor can decrypt. Blob IDs and ciphertext sizes remain visible.                                        |
| Local blob transfer authorization               | A local transfer needs an HMAC-SHA256 link bound to version, method, ID, and expiry; comparison is constant time.                    | The local HMAC secret must be stable and private. Links are bearer capabilities until expiry.                                |
| Relay-event integrity                           | The relay accepts only strictly parsed, Ed25519-signed events, rejects excessive future skew, and enforces explicit expiration.      | Past `createdAt` is not anti-replay policy; durable receipts and IDs provide idempotency.                                    |
| Atomic relay state mutation                     | One accepted event atomically gets a topic sequence, durable receipt, and any author-scoped collapse deletion.                       | Storage backend correctness is required.                                                                                     |
| Crash-safe application consumption              | An application can commit its effect and `ReceivedEvent.advanceCursor(transaction)` in one `MurmurStore` transaction.                | The application must use a genuinely atomic store transaction and advance only after its own writes.                         |
| Stable relay cursors                            | Topic heads never decrease, and expiration or collapse leaves legal sequence holes rather than reusing sequence numbers.             | Applications must advance across trailing holes only from an exhausted page and persist their own cursor durably.            |
| Group membership evolution                      | MLS group epochs use TreeKEM state and cryptographic Commits; removed members do not receive later epoch secrets.                    | The MLS profile is not independently audited; current members can read current group data.                                   |
| Group forward secrecy                           | Group application state advances through MLS epochs and sends ratchet state forward.                                                 | Durable prepare → persist → publish discipline is mandatory for recoverability.                                              |
| Shared-document attribution                     | An operation's actor ID must equal the MLS-authenticated sender leaf supplied to `SharedTextDocument.apply()`.                       | This authenticates only after MLS delivery has been authenticated.                                                           |

## Current design properties that need care

### Signed event age is not replay protection

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

### Collapse is arrival-ordered

The relay applies collapse when it accepts a publication. It does not compare
`createdAt` or inspect an application version, so a delayed publication
carrying older logical state can arrive later and delete newer retained state
from the same author and collapse key.

Applications using collapse must include an authenticated logical version in
the opaque payload and reject regressions when applying events. This ordering
belongs above the untrusted relay boundary: letting the relay interpret an
application version would give it message semantics and would not make a
malicious relay trustworthy.

### Pairwise topics are capability addresses

Topic reads have no identity authentication. Knowing an ID is enough to call
`readEvents`. This is intentional and supports opaque shared objects, but it
means a public-key-derived direct topic would be a privacy bug.

Every relay event must expose `author.signingKey` for relay signature
verification. If direct traffic used a topic derived from a recipient's public
identity key, anyone holding that public token could read the topic and learn
which keys write there and when. `pairwiseTopic(self, peer)` instead derives
the address from an X25519 shared secret plus a fixed domain and both public
encryption keys. Only the two peers can calculate it.

Do not place a pairwise topic ID in logs, URLs, telemetry, or an untrusted
application database unless that disclosure is acceptable.

### Cursors protect durability; they are not acknowledgements

The relay has no delivery queue and no `acknowledge()` operation. A client keeps
one local cursor per relay/topic and an event can advance it only inside a
`MurmurStore` transaction.

```text
received event
    |
    +-- transaction commits application record + next cursor -> not delivered again
    |
    `-- transaction fails or process crashes -> old cursor -> event is read again
```

This protects against a crash between accepting an event and recording its
application effect. It does not create global exactly-once delivery across
relays or replace application-level replay handling. Direct messages provide a
separate sender/message-ID replay marker; MLS channels persist their own replay
fingerprints and epoch checkpoints.

Relay cursors remain stable even when explicit expiration or collapse creates
holes because the topic head never decreases and sequences are never reused.
An application advances across trailing holes only when a page is exhausted;
it must durably record that cursor together with the effects of the page.

## Direct messages are not post-compromise secure

Direct messages use a fresh ephemeral sender X25519 key, but they are sealed to
the recipient's long-term X25519 identity key. If that recipient encryption key
is stolen, an attacker who recorded direct-message envelopes can decrypt past
messages and can decrypt future messages sent to that unchanged key.

There is no direct-message key rotation or post-compromise recovery mechanism.
Groups do better because MLS evolves epoch state and rekeys on membership
changes, but that does not make direct conversations forward secret.

## Identity tokens are the root of trust

Identity tokens are exchanged out of band. Murmur does not verify them, compare
safety numbers, provide key transparency, or bind them to accounts. An attacker
who substitutes their own token in that exchange can establish separately valid
contacts with both parties and defeat all downstream authenticity and
confidentiality expectations.

Use an authenticated out-of-band channel appropriate to the application. The
protocol cannot compensate for a machine-in-the-middle there.

## Metadata exposure

Encryption does not hide:

| Visible to relay/operator       | Why it is visible                                 |
| ------------------------------- | ------------------------------------------------- |
| Topic IDs                       | Routing and storage keys.                         |
| Outer `author.signingKey`       | Required to verify relay-event signatures.        |
| Event timing and request timing | Necessary to serve requests.                      |
| Event and blob sizes            | Necessary to transmit and enforce limits.         |
| Blob IDs                        | SHA-256 content addresses for ciphertext storage. |

Topic IDs are stable while a topic exists and can link related traffic. Pairwise
topics keep this metadata from people who have only public identity tokens, not
from the two participants, the relay operator, or anyone to whom a participant
leaks the topic.

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
- Blob retention is backend-owned and independent of topic retention. Do not
  assume a blob has the same lifetime as the message that referenced it.
- The local backend receives ciphertext bytes and stores them on its filesystem.
  The S3 backend keeps transfer bytes out of the relay process, but its SigV4
  behavior has not been tested against a live bucket or MinIO.

## Rate-limit scope

The default rate limiter is an in-memory, per-process token bucket. It limits
by direct client IP and, for valid event publication, also by outer author
signing key. It ignores `X-Forwarded-For` unless trusted proxies are explicitly
configured.

This prevents basic single-process abuse and makes spoofed forwarded headers
ineffective by default. It is not a distributed rate limit: with `N` instances,
the effective allowance is approximately `N` times larger. A shared
`RateLimiter` implementation is needed for a cluster-wide policy.

## Not protected

Murmur does not currently protect against:

- an unverified or substituted identity token;
- compromise of an endpoint that holds identity keys, local application state,
  group state, or decrypted messages;
- past or future direct-message disclosure after compromise of the recipient
  long-term X25519 key;
- traffic analysis from the visible metadata above;
- relay or network denial of service, censorship, or state deletion;
- disclosure of a topic ID to an unintended reader;
- a malicious current group member reading current group data or writing
  application content it is otherwise authorized to send;
- identity-key rotation or automatic recovery after key loss;
- a live S3/MinIO integration validation of the custom SigV4 implementation;
- a live PostgreSQL validation of the pool adapter, cross-instance
  `LISTEN`/`NOTIFY`, or advisory-lock contention;
- independent cryptographic review or an existing CI safety net.

Applications must also choose safe local storage, backups, logging, token
exchange, TLS termination, and operational access controls. Those choices are
outside the Murmur protocol.

Shared-session revocation has the same endpoint limit. Murmur transactionally
requests local replica deletion and retires its protocol rows, cursors, and
epoch secrets, but cannot erase plaintext or history-page keys a member already
copied. Revocation protects future MLS epochs and page keys; it is not remote
data destruction.

## Stateful facade guarantees

Murmur treats the relay as untrusted ordered storage. The relay sees topic
descriptors, outer author keys, timing, sizes, expiration, and sequence
activity. It does not receive topic secrets, identity secrets, profiles,
friend-control plaintext, group descriptors, MLS application bytes, Welcome
plaintext, or epoch secrets.

## Guarantees

- Friend request and response contents are recipient-confidential,
  identity-authenticated, and outer-author unlinkable.
- Friend control content is pairwise encrypted with distinct directional keys
  and identity-signed.
- Group membership changes are real TreeKEM Commits.
- Removed members cannot authenticate or decrypt later MLS application events.
- Every outbound relay event is stored exactly before network access.
- Ambiguous publication retries the same bytes, ID, author, and signature.
- MLS ratchets never advance only in RAM: cloned post-state and the exact event
  commit atomically.
- Relay order, not publish return order, chooses concurrent Commit winners.
- Invalid retained events cannot permanently stall a topic.
- awaited `close()` and `destroy()` abort convergence, await serialized active
  work, then zero live identity, topic, and epoch secrets.

## Limits

- Public identity keys still need an authenticated out-of-band exchange.
- Compromise of the single identity root gives both Ed25519 signing and the
  converted X25519 key-agreement capability; they are intentionally one
  recovery and compromise domain.
- The public identity inbox is intentionally linkable to that identity.
- A relay can deny service, withhold, reorder, or delete retained data.
- A current group member can read and write current group content.
- Removed members retain the stable relay capability and can inject junk, but
  not valid newer-epoch MLS content.
- Local storage compromise exposes the identity, friend capabilities,
  KeyPackage bundles, and MLS checkpoints held there.
- This implementation has not received an independent cryptographic audit.
