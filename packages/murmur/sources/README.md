# Library sources

```text
accounts/   relay-owned account-device roster state and convergence
chaos/      deterministic fault-injection support
crypto/     identity roots, signatures, key agreement, and hashing
delivery/   signed queue transport, processing, SSE, and WebSocket clients
identity/   application-owned account-secret wrapping and identity boundary
mls/        MLS cryptographic state and protocol operations
services/   typed application routing
sessions/   stateful public client facade and durable session engine
storage/    application-owned transactional store seam
utils/      self-contained encoding and byte helpers
```

`index.ts` is the only package entry point. The published surface remains
browser-safe and side-effect free.
