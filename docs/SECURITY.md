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
- attempt invalid writes, list mutations, and blob uploads;
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
| Relay-event integrity                           | The relay accepts only strictly parsed, Ed25519-signed events within its time window.                                                | This validates the outer relay mutation, not application meaning.                                                            |
| Atomic relay state mutation                     | One accepted event atomically gets a topic sequence, durable receipt, and all snapshot/list mutations.                               | Storage backend correctness is required.                                                                                     |
| Crash-safe application consumption              | An application can commit its effect and `ReceivedEvent.advanceCursor(transaction)` in one `MurmurStore` transaction.                | The application must use a genuinely atomic store transaction and advance only after its own writes.                         |
| Reset safety                                    | A cursor outside retained history is reported as `reset`, and `sync()` cannot return it as ordinary caught-up events.                | The application must call `loadTopic()` and apply the snapshot/list before resuming incremental sync.                        |
| Group membership evolution                      | MLS group epochs use TreeKEM state and cryptographic Commits; removed members do not receive later epoch secrets.                    | The MLS profile is not independently audited; current members can read current group data.                                   |
| Group forward secrecy                           | Group application state advances through MLS epochs and sends ratchet state forward.                                                 | Durable prepare → persist → publish discipline is mandatory for recoverability.                                              |
| Shared-document attribution                     | An operation's actor ID must equal the MLS-authenticated sender leaf supplied to `SharedTextDocument.apply()`.                       | This authenticates only after MLS delivery has been authenticated.                                                           |

## The two current design properties that need care

### Pairwise topics are capability addresses

Topic reads have no identity authentication. Knowing an ID is enough to call
`readState`, `readList`, or `readEvents`. This is intentional and supports
opaque shared objects, but it means a public-key-derived direct topic would be a
privacy bug.

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

Event logs are bounded. An old or invalid future cursor produces `reset`, not a
silent empty read. The client must atomically replace its materialized state
from the snapshot and full list using `loadTopic()`.

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

| Visible to relay/operator                     | Why it is visible                                 |
| --------------------------------------------- | ------------------------------------------------- |
| Topic IDs                                     | Routing and storage keys.                         |
| Outer `author.signingKey`                     | Required to verify relay-event signatures.        |
| Event timing and request timing               | Necessary to serve requests.                      |
| Event, snapshot, list-element, and blob sizes | Necessary to transmit and enforce limits.         |
| Blob IDs                                      | SHA-256 content addresses for ciphertext storage. |

Topic IDs are stable while a topic exists and can link related traffic. Pairwise
topics keep this metadata from people who have only public identity tokens, not
from the two participants, the relay operator, or anyone to whom a participant
leaks the topic.

## Relay and storage limits

- A relay can deny service by refusing, deleting, delaying, or replaying
  ciphertext. Cryptography does not guarantee delivery or availability.
- The relay cannot tell a new device the intent of application state. Clients
  must correctly apply snapshots and lists after a reset.
- Topics without a successful publish for 30 days are deleted, including their
  snapshot, list, retained events, and idempotency receipts. Event bodies
  normally expire after seven days.
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
