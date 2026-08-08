# Security

Murmur protects application content from the relay, not communication metadata.

## Relay visibility

The relay sees:

- sender and recipient public identities;
- exact multicast fanout;
- delivery sizes, timing, TTL, and per-inbox progress;
- IP or trusted-ingress admission metadata;
- the lifetime and timing of recipient SSE connections;
- public signed discovery-bundle bytes uploaded to its five-minute cache.

The relay does not receive identity roots, KeyPackage private keys, Welcome
plaintext, MLS epochs, application plaintext, or application history.

Invitation digests are short-lived bearer capabilities. SHA-256 makes them
unguessable and detects relay substitution, but anyone who obtains a digest may
download its public bundle until expiry. The client always verifies the digest,
signed expiry, identity signature, and KeyPackage signatures; cache presence is
not authentication.

## Trust model

The relay is untrusted for confidentiality and correctness. It can delay, drop,
reorder across inboxes, replay retained ciphertext, equivocate, or become
unavailable. It cannot forge a valid sender delivery or decrypt MLS content.

UUIDv7 order is a relay consistency service, not a cryptographic proof. The MLS
committer rule removes dependence on a shared cross-inbox order. Clients still
validate exact recipients, epoch, sender, committer control, KeyPackage
lifetime, and every cryptographic transition.

SSE transports the same untrusted signed deliveries as bounded queue reads. A
stream is authenticated once when opened and must use TLS. It can replay,
truncate, delay, or reorder records; the client validates strict inbox order and
reconnects from durable progress. SSE receipt never authorizes deletion.

## Durable client invariants

- Persist effects, replay state, and cursor before acknowledging.
- Persist post-ratchet epochs and exact outboxes before publishing.
- Adopt Commits only from authenticated queue echoes.
- Keep active and staged epochs separate until the echo wins.
- Treat malformed authenticated input as terminal queue progress.
- Never let application callbacks mutate the `murmur/` storage namespace.
- Zero temporary secret and plaintext byte arrays in success and error paths.

Losing or rolling back the single-device store can lose identity and MLS state.
The relay cannot reconstruct it. A stale store behind the acknowledged queue
prefix fails explicitly rather than skipping missing MLS state.

## Limits

Pending sessions, buffered events, replay entries, proposals, members, outboxes,
ciphertext, fanout, queue bytes, sender bytes, and global relay storage are all
bounded. Per-sender reference quotas charge multicast fanout, but identities are
free to create: relay quotas bound resource usage, not fair availability under
a Sybil attack. Probabilistic replay overflow can reject legitimate new traffic
but never exposes a probable replay to the application.

Relay UUIDv7 time is an untrusted ordering input. The inbox processor accepts
its magnitude only inside a bounded local plausibility window before using it
for expiry and replay garbage collection. A malicious relay can still delay
traffic within that window; MLS generation and epoch validation remain the
cryptographic backstop.

## Deployment requirements

- Terminate TLS before the Node relay.
- Apply non-Sybil authenticated admission before forwarding and enforce an
  outstanding-fanout budget per admitted principal. A socket-address rate
  limit alone is not sufficient for a public relay.
- Protect the client store as identity and epoch secret material.
- Back up client state atomically; restoring a stale backup may be
  unrecoverable.
- Monitor queue, sender, and global backpressure.
- Monitor separate invitation-cache item and byte backpressure.

Murmur has not received an independent security audit. Its MLS implementation
is a tested RFC 9420 profile, not a claim of complete RFC feature coverage.
