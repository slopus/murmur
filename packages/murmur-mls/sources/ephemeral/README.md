# Ephemeral MLS frames

Authenticated, epoch-scoped, non-durable framing for an existing MLS group.
This module exists so a group can carry traffic that is wrong to write down —
terminal bytes, cursor motion, a resize — without a second group, a second key
agreement, or a second trust root.

```text
current epoch
     |
     | RFC 9420 MLS-Exporter("murmur ephemeral channel v1", shareId)
     v
channel secret (32 bytes, never stored)
     |
     +-- ExpandWithLabel(senderLeaf || streamId) --> key(16) + nonceBase(12)
                                |
     header(36) || Ed25519 signature(64) || AES-128-GCM ciphertext
```

The header is `version(1) | type(1) | epoch(8) | senderLeaf(2) |
streamId(16) | counter(8)`. It is cleartext, but it is covered by both the AEAD
associated data (together with the group ID) and the signature, so the relay
learns only that opaque bytes moved.

## Why the exporter and not the application ratchet

`MlsEpochState.seal()` advances the Secret Tree, which is exactly the state a
correct application must checkpoint before publishing. An ephemeral frame must
not create that obligation. The exporter reads the epoch's exporter secret
instead, touches no ratchet, and advances no persistence generation, so a frame
can be sent and forgotten. Every Commit produces an unrelated exporter secret,
which is what makes revocation apply to this channel unchanged.

## Why a signature on top of the AEAD

Every member of an epoch holds the same exported channel secret, so the AEAD
alone would let one member forge another member's frames. Each frame is
therefore also signed with the sender's MLS leaf signature key.

## Bounds

Nothing here grows without a limit. One payload is at most 64 KiB. A receiver
tracks at most 8 stream identifiers per sender and 256 senders, evicting the
least recently used, and rejects a counter it has already accepted. A sender
rotates to a fresh random stream identifier — and therefore a fresh key — long
before its counter could wrap.

Evicting a stream keeps its high-water counter as a tombstone, bounded at 64
per sender, so flushing the live table does not reopen a retired stream's
frames to replay. The residual is deliberate and worth knowing: replaying one
stream requires first evicting its tombstone, which takes 8 live plus 64
retired — 73 validly signed stream identifiers from that same authenticated
sender. Tombstones are keyed by the authenticated leaf, so no other member can
flush them. That is bounded memory bought at a much higher replay bar, not
replay protection that never expires.

The random per-instance stream identifier is what makes an in-memory counter
safe. A restarted sender picks a new identifier and a new key, so a nonce is
never reused across restarts, and no counter is ever written to disk.

## Hostile input is a drop, not an error

`open()` returns a drop reason rather than throwing. This channel is lossy by
construction, so a forged, stale, replayed, or malformed frame is a routine
event that the caller counts.

The signature is checked before the epoch is read. A frame naming a different
epoch reports that epoch, which is the earliest warning available that
membership changed — and precisely because an application reacts to it, it is
only ever reported for a frame that verified under a leaf key of the current
epoch. Nothing reachable before the signature check allocates keyed state or
names an epoch.
