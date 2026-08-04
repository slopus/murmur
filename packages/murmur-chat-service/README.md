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
- source/blob operations default to, and cannot exceed, 30 seconds.

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

One live `ChatService` per store object is permitted in a JavaScript realm.
Failed outbox intents retain strict durable error codes and do not stop other
outboxes or inbound projection; callers explicitly `retry`, `cancel`, or
`drop` them. Projection, cursor, dedupe, delivered, and quarantine records are
derived and can be safely refolded with `rebuild`.
