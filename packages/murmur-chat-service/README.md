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

The package is intentionally not published. Blob retention and deletion are
backend policy; the service does not promise erasure.
