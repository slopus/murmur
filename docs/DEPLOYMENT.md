# Relay deployment

The standalone relay requires Node 22.5 or later and supports SQLite or
Postgres.

## SQLite

```bash
pnpm --filter @slopus/murmur-relay build

MURMUR_RELAY_STORE=sqlite \
MURMUR_RELAY_DB=./data/murmur-relay.sqlite \
MURMUR_RELAY_ORIGINS=https://app.example \
pnpm --filter @slopus/murmur-relay start
```

SQLite is appropriate for one relay process. The store uses WAL mode,
foreign-key enforcement, a busy timeout, and bounded write transactions.

## Postgres

```bash
MURMUR_RELAY_STORE=postgres \
MURMUR_RELAY_DB=postgres://user:password@db.example/murmur \
MURMUR_RELAY_ORIGINS=https://app.example \
pnpm --filter @slopus/murmur-relay start
```

Postgres supports multiple relay processes. LISTEN/NOTIFY wakes long polls and
SSE streams across processes; durable reads always come from tables, so
notifications are not data. Write paths serialize through the global
quota/UUID row.

## Startup verification and logs

The process checks its dependencies before listening for traffic. SQLite must
answer its health query. Postgres must complete schema initialization, answer a
health query, and establish the dedicated `LISTEN` connection used for
cross-instance wakes. Any failure closes resources and exits non-zero without
binding the HTTP port.

Lifecycle logs go to standard output as single lines. A successful boot includes:

```text
relay:store-open-complete backend=postgres
relay:connectivity-check-complete backend=postgres
relay:ready backend=postgres host=0.0.0.0 port=8787
relay:maintenance-ready intervalMilliseconds=10000 budgetMilliseconds=1000
```

Failures report the last stage plus a sanitized error type, code, and message.
Connection URLs and credentials are redacted. `SIGINT` and `SIGTERM` log each
HTTP and storage shutdown stage.

For Kubernetes:

```bash
kubectl logs deployment/murmur-relay
kubectl logs deployment/murmur-relay --previous
kubectl describe pod -l app.kubernetes.io/name=murmur-relay
```

## Network boundary

The bundled host binds `HOST` (default `0.0.0.0`) and `PORT` (default `8787`)
using plain HTTP. Put it behind TLS termination. Do not expose it directly.

The host rate-limits by socket peer. Behind a trusted proxy that overwrites a
client-address header, configure:

```bash
MURMUR_RELAY_REMOTE_ADDRESS_HEADER=x-real-ip
MURMUR_RELAY_REQUESTS_PER_MINUTE=600
MURMUR_RELAY_TRACKED_ADDRESSES=10000
```

Never trust a forwarding header that clients can supply unchanged.

The reverse proxy must support long-lived unbuffered SSE responses on
`POST /v1/queue/events`. Disable response buffering and compression for
`text/event-stream`, allow at least 45 seconds of idle time, and preserve
disconnect propagation. The relay emits a heartbeat every 15 seconds.

## Invitation cache

The same admission principal and request limiter apply to invitation uploads
and downloads. The maximum lifetime is fixed at five minutes. Optional cache
bounds are:

```bash
MURMUR_RELAY_INVITATION_BYTES=16384
MURMUR_RELAY_INVITATION_ITEMS_PER_PRINCIPAL=32
MURMUR_RELAY_INVITATION_BYTES_PER_PRINCIPAL=524288
MURMUR_RELAY_GLOBAL_INVITATION_ITEMS=10000
MURMUR_RELAY_GLOBAL_INVITATION_BYTES=67108864
```

Cached bundles are public signed material, not encrypted application data.
They are non-enumerable and addressable only by their 32-byte SHA-256 digest.

## Maintenance

The standalone process starts bounded delivery and invitation expiration
pruning every ten seconds, skips overlapping runs, and drains within a
one-second time budget. Publish and acknowledgement paths also commit one
bounded prune batch before their own transaction, so expired backlog cannot
permanently block quota recovery.

Back up the database as ordinary pending delivery infrastructure. A relay
restore can replay or lose pending ciphertext; application correctness must
remain idempotent and client state remains authoritative.
