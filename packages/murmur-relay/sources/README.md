# Relay sources

```text
cloudflare/  Worker and Durable Object implementation
fanout/      durable manifest-first multicast coordinator
http/        standalone Fetch request boundary
protocol/    signed delivery and queue request codecs
relay/       queue service and wake coordination
server/      Node HTTP adapter
session/     short-lived relay-session tickets
storage/     SQLite and PostgreSQL queue stores
utils/       strict JSON, logging, bytes, and UUID helpers
websocket/   authenticated WebSocket protocol
```

The relay stores opaque pending ciphertext, continuity metadata, current
account rosters, account-linked directory state, and relay-visible session
routing policy. Standalone stores keep all cascades in one database transaction;
Cloudflare commits singleton control deletion first and completes per-device
inbox deletion through a durable alarm-retried cascade.
