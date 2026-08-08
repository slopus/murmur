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

Postgres supports multiple relay processes. LISTEN/NOTIFY reduces long-poll
latency; durable reads always come from tables, so notifications are not data.
Write paths serialize through the global quota/UUID row.

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

## Maintenance

The standalone process starts bounded expiration pruning every ten seconds,
skips overlapping runs, and drains within a one-second time budget. Publish and
acknowledgement paths also commit one bounded prune batch before their own
transaction, so expired backlog cannot permanently block quota recovery.

Back up the database as ordinary pending delivery infrastructure. A relay
restore can replay or lose pending ciphertext; application correctness must
remain idempotent and client state remains authoritative.
