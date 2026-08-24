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

For revocable invitations it also sees the invitation owner's public identity,
a separate public revocation key, and signatures authorizing registration and
revocation. The private revocation root remains in the creator's store. Relay
logs must never include invitation digests, bundle bytes, authorization bodies,
or revocation signatures.

Invitation digests are short-lived bearer capabilities. Signed bundles contain
unpredictable cryptographic material, making their 32-byte digests infeasible to
guess; SHA-256 also detects relay substitution. Anyone who obtains a digest may
download its public bundle until expiry. The client always verifies the digest,
signed expiry, identity signature, and KeyPackage signatures; cache presence is
not authentication.

Possessing a digest grants download but not revocation. The owner signature
binds an exact digest and expiry to a separate revocation public key, and the
relay accepts revocation only under that key. A live revocation creates an
expiring tombstone so replaying the public invitation bytes cannot resurrect
the cache entry. Revocation is not retroactive session termination.

If the relay is unavailable, the creator immediately destroys matching unused
private KeyPackages and retains a durable pending revocation. That prevents a
new Welcome from completing at the creator, but no client-side action can make
an unreachable relay stop serving already-cached public bytes. Global cache
invalidation therefore occurs only after authenticated retry or five-minute
expiry.

Confirmed contacts exchange fifteen one-use KeyPackages and one reusable
last-resort KeyPackage inside their authenticated technical session. Normal
group admission deletes private KeyPackage material after one Welcome. The
fallback deliberately remains available across multiple Welcomes so an offline
contact can always be added after the one-use pool is exhausted. Compromise of
that retained fallback can therefore expose captured Welcomes addressed to it;
the tradeoff is explicit availability rather than deletion-based Welcome
forward secrecy. Refill rotates the fallback when the contact reconnects.

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

- Persist protocol effects, buffered updates, replay state, and cursor before
  acknowledging.
- Commit one identity-wide update batch only after `onUpdates` resolves; use
  stable update IDs when application persistence needs idempotency.
- Persist post-ratchet epochs and exact outboxes before publishing.
- Commit a local contact profile revision, all active-contact mirrors, and all
  corresponding outboxes in one transaction.
- Persist invitation revocation authority and pending local key destruction
  across restart; never serialize the private authority into an invitation.
- Adopt Commits only from authenticated queue echoes.
- Keep active and staged epochs separate until the echo wins.
- Treat malformed authenticated input as terminal queue progress.
- Never expose the `murmur/` storage namespace or transaction to application
  callbacks.
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
- Monitor separate invitation-cache item, byte, revocation-authority, and
  tombstone backpressure.

Murmur has not received an independent security audit. Its MLS implementation
is a tested RFC 9420 profile, not a claim of complete RFC feature coverage.
