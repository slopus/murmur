# `@murmur/chat-service`

Private, browser-safe generic chat semantics above `@slopus/murmur`. The
application owns message and attachment-metadata codecs, persistence, and blob
transport; this package owns durable delivery, projection, and attachment
cryptography.

```text
application codecs + attachment sources
                 |
          ChatService
        /      |       \
MurmurStore  Murmur   BlobStore
 chat/v1/    groups   ciphertext only
```

The package is intentionally not published.

## Enforced v1 limits

- messages use a strict binary frame no larger than Murmur's 256 KiB
  application-event limit;
- each message has at most 8 attachments;
- each attachment is at most 100 MiB and uses 256 KiB plaintext chunks;
- history and durable scans page at no more than 100 and 64 records
  respectively;
- whole-file downloads default to a 16 MiB allocation cap;
- source hashing/encryption defaults to and cannot exceed 30 seconds;
- blob PUT/readback defaults to 30 seconds and may be configured up to 30
  minutes for large objects;

Relay sequence is canonical order. A durable monotonic enqueue sequence
preserves local backlog order before handoff. `messageId` is only retry/dedupe
material: identical `(sender, messageId, authenticated-frame digest)` retries
collapse, while different digests remain distinct. Public `eventId` is the
stable conversation-and-relay-sequence identity.

## Attachments and hostile storage

```text
plaintext source --one encryption pass--> durable ciphertext stage
                                             |
                           unconditional content-addressed PUT
                                             |
                          head + every range + SHA-256 verify
```

The blob backend receives ciphertext only and is treated as hostile. Downloads
authenticate each chunk before yielding plaintext. Source and backend range
buffers remain owned by their provider and are never mutated. Buffers yielded
to `BlobStore.put` are borrowed for that iteration and must be copied by a
backend that retains them.

Empty files encrypt to one authenticated 16-byte tag, so they do not share the
global SHA-256 of an empty blob. Random per-send keys and file IDs prevent
cross-sender or equal-plaintext blob dedupe. The backend still observes exact
ciphertext size and timing.

## Retention and capability lifetime

Blob TTL and deletion are backend policy. Chat does not promise erasure.
Removing a member prevents new MLS history but cannot revoke attachment
capabilities that member already retained. Applications may explicitly call
`destroyAttachment` to zero their in-memory capability copy.

One live `ChatService` per durable namespace is permitted in a JavaScript process.
Failed outbox intents retain strict durable error codes and do not stop other
outboxes or inbound projection; callers explicitly `retry`, `cancel`, or
`drop` them. Cancellation reports `cancelled` or `may-have-delivered`, because
Murmur handoff cannot be revoked. `outbox({ after, limit })` is paged and
returns an opaque `nextAfter`.

Completed staged ciphertext survives network timeouts and retries byte-for-byte
without key/nonce reuse. Partial source staging rotates keys before retry.
Orphan, partial, and uploaded staging records are page-collected on open and
convergence.

Projection, cursor, dedupe, delivered, and quarantine records are derived and
can be safely refolded with `rebuild`. Arbitrary partial external deletion
should be followed by `rebuild`; resumable rebuild markers make interrupted
supported resets safe.

Chunks yielded by `openAttachment` are caller-owned. Applications should zero
them after use when their lifetime matters.

The durable lease detects two wrappers over the same namespace within one
JavaScript process. A generic application-provided store cannot provide a
portable cross-process lease, so applications must enforce exclusive ownership
across processes.
