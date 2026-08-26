# Murmur Relay

`@slopus/murmur-relay` is private deployment infrastructure for authenticated
encrypted identity queues. It stores only bounded, unacknowledged, unexpired
ciphertext, continuity metadata, current device rosters, and account-linked
directory prekey pools.

## Backends

- SQLite through Node's built-in `node:sqlite` support.
- PostgreSQL through `pg`, with database-backed wake notifications.
- Cloudflare Durable Objects for inboxes, manifest-first fanout, and singleton
  SQLite roster, directory, and relay-visible session control state.

Cloudflare session publications derive exact current-device recipients from the
singleton control database. Terminal account deletion removes control state
before replying, then durably retries its asynchronous per-device inbox purge.
`deriveCloudflareDirectoryTicketSecret()` gives the application ticket issuer
the domain-separated seed expected by Cloudflare directory claims.

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

| Method | Path                        | Purpose                            |
| ------ | --------------------------- | ---------------------------------- |
| `GET`  | `/health`                   | Storage and wake-source readiness  |
| `POST` | `/v1/deliveries`            | Atomic signed ciphertext multicast |
| `POST` | `/v1/sessions/delete`       | Signed terminal session purge      |
| `POST` | `/v1/accounts/delete`       | Signed terminal account cascade    |
| `POST` | `/v1/queue/read`            | Signed bounded inbox read          |
| `POST` | `/v1/queue/events`          | Authenticated ordered SSE stream   |
| `POST` | `/v1/queue/ack`             | Signed monotonic prefix trim       |
| `POST` | `/v1/device-rosters/read`   | Exact current roster lookup        |
| `POST` | `/v1/device-rosters/mutate` | Signed roster mutation             |
| `POST` | `/v1/directory/upload`      | Signed per-device prekey state     |
| `POST` | `/v1/directory/claim`       | Ticketed exact-account claim       |

Directory construction requires a `DirectoryTicketVerifier`. Production
deployments should connect it to their authentication server. The exported
`LocalDirectoryTicketIssuer` is suitable for local deployments and tests; its
tickets carry an expiry and atomic exact-claim budget.

Account deletion is account-signed and replay-protected. SQLite and PostgreSQL
remove the complete ownership cascade in one transaction and return the same
success for an authenticated account with no retained state.

See [deployment](../../docs/DEPLOYMENT.md) and the complete
[relay API](../../docs/RELAY_API.md).

## Development

```bash
pnpm --filter @slopus/murmur-relay test
pnpm --filter @slopus/murmur-relay check
pnpm --filter @slopus/murmur-relay build
```
