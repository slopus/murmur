# Core source layout

```text
crypto/              one-root Ed25519/X25519 identity primitives
contacts/            built-in mutual-profile contact protocol and state
delivery/            signed pages/SSE, HTTP transport, durable inbox processor
identity/discovery/  signed KeyPackage bundles and digest-cache transport
mls/                 browser-safe RFC 9420 profile
sessions/            public stateful MLS coordinator
services/            optional typed session ownership and scoped persistence
storage/             transactional durable-store contract and memory store
utils/               bounded serialization and byte utilities
index.ts             root package exports
```

The public façade is `MurmurClient` in `sessions/`. Delivery queues and ordered
SSE are transport buffers; durable protocol state always crosses `storage/`.
