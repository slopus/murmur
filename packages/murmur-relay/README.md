# Murmur Relay

`@slopus/murmur-relay` is private deployment infrastructure for authenticated
encrypted identity queues. It stores only bounded, unacknowledged, unexpired
ciphertext and continuity metadata.

## Backends

- SQLite through Node's built-in `node:sqlite` support.
- PostgreSQL through `pg`, with database-backed wake notifications.
- Cloudflare Durable Objects for inboxes and manifest-first fanout.

## Run locally

```bash
pnpm --filter @slopus/murmur-relay build
MURMUR_RELAY_STORE=sqlite \
MURMUR_RELAY_DB=./data/murmur-relay.sqlite \
pnpm --filter @slopus/murmur-relay start
```

The default listener is `0.0.0.0:8787`. Configure exact CORS origins, trusted
remote-address handling, per-address request limits, and ingress-principal
fanout limits before exposing the process publicly.

## HTTP routes

| Method | Path               | Purpose                            |
| ------ | ------------------ | ---------------------------------- |
| `GET`  | `/health`          | Storage and wake-source readiness  |
| `POST` | `/v1/deliveries`   | Atomic signed ciphertext multicast |
| `POST` | `/v1/queue/read`   | Signed bounded inbox read          |
| `POST` | `/v1/queue/events` | Authenticated ordered SSE stream   |
| `POST` | `/v1/queue/ack`    | Signed monotonic prefix trim       |

See [deployment](../../docs/DEPLOYMENT.md) and the complete
[relay API](../../docs/RELAY_API.md).

## Development

```bash
pnpm --filter @slopus/murmur-relay test
pnpm --filter @slopus/murmur-relay check
pnpm --filter @slopus/murmur-relay build
```
