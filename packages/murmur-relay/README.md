# `@slopus/murmur-relay`

Private Murmur infrastructure implementing authenticated encrypted identity
queues. The relay sees sender and recipient identities, exact fanout, timing,
TTL, and queue progress. It never sees MLS or application plaintext.

## Contract

- One ordered inbound queue per public identity.
- One relay-assigned UUIDv7 event ID per atomic multicast.
- Event IDs are time ordered and strictly monotonic within each inbox.
- One queue reference per exact recipient.
- Sender-scoped delivery IDs deduplicate while any reference remains.
- Signed reads prove ownership of the recipient identity.
- Recipient-authenticated SSE emits each exact queued delivery in inbox UUIDv7
  order with pull-driven backpressure.
- Signed monotonic acknowledgements trim one processed queue prefix.
- A delivery disappears after every reference is acknowledged or it expires.
- Per-recipient, per-sender, and relay-wide item/byte/reference quotas make
  publication all-or-nothing and bound pending storage. Sender reference quota
  charges multicast fanout rather than only ciphertext records.
- Every trusted-ingress principal has an exact outstanding-reference quota.
  References leave that quota when recipients acknowledge or TTL removes them.
- Signed public discovery bundles may be cached for at most five minutes under
  the SHA-256 digest of their exact bytes.
- Invitation lookups are non-enumerable and have separate per-principal and
  relay-wide item and byte quotas. Re-upload does not extend expiry.

There are no topics, snapshots, retained history, collapse keys, lists, or
anonymous capability addresses.

## Run

The standalone host speaks plain HTTP and must run behind TLS termination in
production. Public identities are free to create, so relay quotas do not
provide Sybil resistance. The ingress must authenticate a non-Sybil principal
and enforce an outstanding-fanout budget before forwarding; the bundled
per-address limiter is only a local safety bound. Do not expose the shown
`0.0.0.0` listener directly to the internet: signed queue reads and
acknowledgements are replayable inside their short clock-skew window.

```bash
pnpm --filter @slopus/murmur-relay build
MURMUR_RELAY_STORE=sqlite \
MURMUR_RELAY_DB=./data/murmur-relay.sqlite \
MURMUR_RELAY_ORIGINS='https://app.example' \
pnpm --filter @slopus/murmur-relay start
```

Set `MURMUR_RELAY_STORE=postgres` and provide a Postgres URL in
`MURMUR_RELAY_DB` for the Postgres backend. Node 22.5 or later is required.
The direct command is suitable for local development; production traffic must
arrive through the TLS and admission boundary described above.

Behind a trusted admission proxy that overwrites a client-address or principal
header, set
`MURMUR_RELAY_REMOTE_ADDRESS_HEADER` to that header name. Admission limits are
configurable with `MURMUR_RELAY_REQUESTS_PER_MINUTE` and
`MURMUR_RELAY_TRACKED_ADDRESSES`. The exact outstanding fanout allowed for one
admitted principal is configured with `MURMUR_RELAY_ADMISSION_REFERENCES`. The
default is 10,000 references, one percent of the default global ceiling.
Invitation cache limits are configured with
`MURMUR_RELAY_INVITATION_BYTES`,
`MURMUR_RELAY_INVITATION_ITEMS_PER_PRINCIPAL`,
`MURMUR_RELAY_INVITATION_BYTES_PER_PRINCIPAL`,
`MURMUR_RELAY_GLOBAL_INVITATION_ITEMS`, and
`MURMUR_RELAY_GLOBAL_INVITATION_BYTES`. Defaults are 16 KiB per bundle, 32
items and 512 KiB per admitted principal, and 10,000 items or 64 MiB globally.
The five-minute maximum TTL is not configurable above five minutes.

The queue schema is intentionally incompatible with the former topic relay.
Startup fails when legacy `murmur_relay_*` tables are present; deploy with a
clean SQLite database or Postgres schema rather than retaining old ciphertext.

The standalone process drains expired data every ten seconds in fixed
transactions, continuing for at most one second per tick. It skips overlapping
ticks rather than building an unbounded maintenance queue.

## Startup and shutdown logs

The standalone process writes one human-readable line per lifecycle stage to
standard output. Startup reports configuration parsing, store creation, the
connectivity check, listener binding, maintenance scheduling, and readiness.
It does not open the HTTP port until the backing store responds and the wake
source is ready. For Postgres, this means both a database health query and the
dedicated `LISTEN` connection must succeed.

Fatal lines include a `stage`, safe driver error `code`, and sanitized `message`.
Database URLs, credentials, tokens, and stacks are never logged. Graceful
`SIGINT` and `SIGTERM` shutdown reports HTTP and service closure independently,
so a failure in one cleanup path does not skip the other.

For a Kubernetes crash loop, inspect both the current and previous container:

```bash
kubectl logs deployment/murmur-relay
kubectl logs deployment/murmur-relay --previous
kubectl describe pod -l app.kubernetes.io/name=murmur-relay
```

The last successful `relay:*` stage identifies where startup stopped. A healthy
boot ends with `relay:ready` followed by `relay:maintenance-ready`.

## HTTP API

| Method | Route                     | Purpose                                   |
| ------ | ------------------------- | ----------------------------------------- |
| `GET`  | `/health`                 | Store health                              |
| `POST` | `/v1/invitations`         | Cache exact signed discovery bytes        |
| `GET`  | `/v1/invitations/:digest` | Fetch unexpired bytes by SHA-256          |
| `POST` | `/v1/deliveries`          | Publish one atomic encrypted multicast    |
| `POST` | `/v1/queue/read`          | Authenticated queue read or long poll     |
| `POST` | `/v1/queue/events`        | Ordered recipient-authenticated SSE       |
| `POST` | `/v1/queue/ack`           | Authenticated monotonic queue-prefix trim |
