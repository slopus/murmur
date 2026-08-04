# Relay protocol

Strict codecs and canonical Ed25519 authentication for typed topic descriptors,
durable events, and protected-read challenges. Topic IDs are SHA-256 hashes of
canonical `(type, name, authorization key(s))` descriptors.

```text
typed topic descriptor -> canonical JSON -> SHA-256 topic ID
event fields ----------> canonical bytes -> author signature
read challenge + tuple -> canonical proof -> capability signature
```

Only these normalized values cross into relay policy and ordered storage.
