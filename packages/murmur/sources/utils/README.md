# Utilities

Small browser-safe helpers shared by all domains: byte concatenation, UTF-8,
base64url, and deterministic JSON encoding. No utility owns protocol state.

```text
Uint8Array <-> UTF-8/base64url
      |
      +-- concatenate/copy/constant-time compare
      `-- canonical JSON bytes -> hashes and signatures
```

Keeping these helpers stateless lets crypto, transport, and durable codecs
share exact encodings without importing one another's domains.
