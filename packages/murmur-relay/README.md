# `@slopus/murmur-relay`

Private Murmur infrastructure implementing authenticated encrypted identity
queues. The relay sees sender and recipient identities, exact fanout, timing,
TTL, and queue progress. It never sees MLS or application plaintext.

## Cloudflare Durable Objects

The additive Worker deployment uses one inbox Durable Object per device, one
deployment-wide sequencing/fanout Durable Object, and one private-group
Durable Object per opaque group. Production and staging are isolated by
`wrangler.production.jsonc` and `wrangler.staging.jsonc`, with separate Worker
names, Durable Object namespaces, endpoints, ticket secrets, and private-group
secrets. Configure each exact public `MURMUR_RELAY_ENDPOINT`, then install both
`MURMUR_RELAY_TOKEN_SECRET` and a distinct canonical 32-byte base64url
`MURMUR_PRIVATE_GROUP_SECRET` with `wrangler secret put <name> --config
<config>`. Run `pnpm cloudflare:deploy:production` or
`pnpm cloudflare:deploy:staging` from this package.

The application server issues tickets with `createRelaySessionFetchHandler`.
Its authorization callback must authenticate the user and verify that the
requested device key belongs to that account. Return the configured Worker
endpoint and a stable admission principal from that callback.

## Contract

- One ordered inbound queue per public identity.
- The legacy HTTP relay assigns one UUIDv7 event ID per atomic multicast.
- Negotiated publication durably records one globally sequenced fanout manifest
  before acceptance, then retries idempotent per-device insertion until every
  target completes or the signed delivery expires.
- Event IDs are time ordered and strictly monotonic within each inbox.
- Every inbox reference also has a strictly increasing sequence, and every
  inbox exposes a 32-byte loss generation.
- One queue reference per exact recipient.
- Sender-scoped delivery IDs deduplicate while any reference remains.
- Signed reads prove ownership of the recipient identity.
- Recipient-authenticated SSE emits each exact queued delivery in inbox UUIDv7
  order with pull-driven backpressure.
- Signed monotonic acknowledgements trim one processed queue prefix.
- Unacknowledged deliveries are retained for at most exactly 180 days. Expiry
  advances each affected inbox generation; acknowledgement never does.
- Per-recipient, per-sender, and relay-wide item/byte/reference quotas make
  publication all-or-nothing and bound pending storage. Sender reference quota
  charges multicast fanout rather than only ciphertext records.
- Every trusted-ingress principal has an exact outstanding-reference quota.
  References leave that quota when recipients acknowledge or TTL removes them.
- Signed public discovery bundles may be cached for at most five minutes under
  the SHA-256 digest of their exact bytes.
- Invitation lookups are non-enumerable and have separate per-principal and
  relay-wide item and byte quotas. Re-upload does not extend expiry, and a live
  revocation tombstone rejects re-upload entirely.
- Owner-authorized uploads bind an invitation to a separate public revocation
  key. Signed single/all revocation replaces live rows with bounded expiring
  tombstones, so public bundle bytes cannot resurrect a revoked digest.

There are no topics, snapshots, retained history, collapse keys, lists, or
anonymous capability addresses.

Each application device uses an independent Murmur root, MLS leaf, local store,
and inbox. An application account may authorize several such device keys, but
the relay never stores their secret material and does not merge their MLS state.

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
MURMUR_PRIVATE_GROUP_SECRET='<canonical-32-byte-base64url>' \
MURMUR_RELAY_ORIGINS='https://app.example' \
pnpm --filter @slopus/murmur-relay start
```

After restoring relay storage from backup, start once with
`MURMUR_RELAY_DECLARE_RESTORED=1`. This explicitly randomizes known inbox
generations and the unopened-inbox seed so clients reset rather than silently
accept missing deliveries. Ordinary startup never rotates continuity state.

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
`MURMUR_RELAY_INVITATION_ITEMS_PER_REVOCATION_KEY`,
`MURMUR_RELAY_GLOBAL_INVITATION_ITEMS`, and
`MURMUR_RELAY_GLOBAL_INVITATION_BYTES`. Defaults are 16 KiB per bundle, 32
items and 512 KiB per admitted principal, 32 items per revocation authority,
and 10,000 items or 64 MiB globally. The five-minute maximum TTL is not
configurable above five minutes.

The Cloudflare negotiated WebSocket Worker does not implement the HTTP
invitation cache. Applications using it must configure a compatible external
`DiscoveryTransport`; deploying the Worker alone does not provide invitation
revocation.

The Murmur 0.5.0 beta line and its fresh relay schema are the compatibility
baseline. Pre-beta SQLite databases, Postgres schemas, client state, and wire
formats are unsupported and are not migrated; deploy the baseline with an empty
relay. Every later schema upgrade must migrate in place while preserving
pending relay data and must not require a clean database.

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
| `POST` | `/v1/invitations`         | Cache legacy unrevocable discovery bytes  |
| `POST` | `/v1/invitations/owned`   | Cache owner-authorized revocable bytes    |
| `POST` | `/v1/invitations/revoke`  | Revoke one or all owner invitations       |
| `GET`  | `/v1/invitations/:digest` | Fetch unexpired bytes by SHA-256          |
| `POST` | `/v1/deliveries`          | Publish one atomic encrypted multicast    |
| `POST` | `/v1/queue/read`          | Authenticated queue read or long poll     |
| `POST` | `/v1/queue/events`        | Ordered recipient-authenticated SSE       |
| `POST` | `/v1/queue/ack`           | Authenticated monotonic queue-prefix trim |
