# Core source layout

```text
crypto/              one-root Ed25519/X25519 identity primitives
delivery/            signed queue wire format, HTTP transport, inbox processor
identity/discovery/  signed public KeyPackage bundles
mls/                 browser-safe RFC 9420 profile
sessions/            public stateful MLS coordinator
storage/             transactional durable-store contract and memory store
utils/               bounded serialization and byte utilities
index.ts             root package exports
```

The public façade is `MurmurClient` in `sessions/`. Delivery queues are
transport buffers; durable protocol state always crosses `storage/`.
