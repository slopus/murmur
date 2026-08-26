# Deployment

## Standalone relay

Node 22.5 or later is required. Build and start from the workspace root:

```bash
pnpm --filter @slopus/murmur-relay build
pnpm --filter @slopus/murmur-relay start
```

SQLite is the default:

```bash
MURMUR_RELAY_STORE=sqlite
MURMUR_RELAY_DB=./data/murmur-relay.sqlite
HOST=0.0.0.0
PORT=8787
```

PostgreSQL uses a connection URL and a database-backed wake channel:

```bash
MURMUR_RELAY_STORE=postgres
MURMUR_RELAY_DB=postgres://user:password@host/database
```

Operational options:

- `MURMUR_RELAY_ORIGINS`: `*` or a comma-separated exact allowlist;
- `MURMUR_RELAY_REMOTE_ADDRESS_HEADER`: trusted proxy address header;
- `MURMUR_RELAY_REQUESTS_PER_MINUTE`: per-address POST limit;
- `MURMUR_RELAY_TRACKED_ADDRESSES`: bounded limiter cardinality;
- `MURMUR_RELAY_ADMISSION_REFERENCES`: outstanding fanout per ingress principal;
- `MURMUR_RELAY_DECLARE_RESTORED=1`: declare a restored database and rotate
  inbox continuity generations before listening.

Use durable storage, TLS, bounded request bodies, and a trusted authenticated
ingress that assigns admission principals. Public queue identities are cheap to
create and are not themselves Sybil resistance.

## Cloudflare relay

The Worker configuration binds:

- `MURMUR_INBOXES` to `MurmurInboxDurableObject`;
- `MURMUR_FANOUT` to `MurmurFanoutDurableObject`;
- `MURMUR_RELAY_TOKEN_SECRET` as a secret;
- `MURMUR_RELAY_ENDPOINT` as the exact public `wss:` endpoint.

Deploy staging or production with the package scripts:

```bash
pnpm --filter @slopus/murmur-relay cloudflare:deploy:staging
pnpm --filter @slopus/murmur-relay cloudflare:deploy:production
```

The application's authenticated server issues short-lived relay session
tickets. The Worker verifies each ticket before upgrading to WebSocket. Durable
Objects retain bounded pending deliveries and alarms prune expiry.

The Cloudflare adapter is queue-only and cannot perform the cross-roster,
directory, inbox, and outbound-state transaction required by terminal account
deletion. `delete_account` returns `501 account_deletion_unavailable`; use the
standalone SQLite or PostgreSQL relay when that API is required.

## Health and shutdown

Do not route traffic until `/health` succeeds. On shutdown, stop accepting new
requests, drain in-flight work, close the wake source and database, then exit.
Monitor publication rejection rates, pending bytes and references, prune work,
continuity resets, wake reconnects, and HTTP/WebSocket error rates.
