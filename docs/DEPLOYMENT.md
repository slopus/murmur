# Relay deployment

The standalone relay requires Node 22.5 or later and supports SQLite or
Postgres.

## Cloudflare Durable Objects

The alternative negotiated transport has isolated production and staging
deployments configured in `packages/murmur-relay/wrangler.production.jsonc`
and `packages/murmur-relay/wrangler.staging.jsonc`. Each deployment uses one
Durable Object per device inbox, one deployment-wide Durable Object for UUIDv7
sequencing and durable ordered fanout retry, and one private-group Durable
Object per opaque group identifier. The public Worker is the required ingress;
clients do not address a Durable Object instance directly.

Set the exact public `wss:` URL in each deployment's `MURMUR_RELAY_ENDPOINT`,
then provision a 32-byte-or-longer base64url HMAC secret in that relay Worker
and the corresponding application server. Private-group state additionally
requires an independent, canonical unpadded base64url secret containing
exactly 32 bytes. Production and staging use separate values, and the
private-group secret must not reuse the relay ticket secret:

```bash
cd packages/murmur-relay
wrangler secret put MURMUR_RELAY_TOKEN_SECRET --config wrangler.production.jsonc
wrangler secret put MURMUR_PRIVATE_GROUP_SECRET --config wrangler.production.jsonc
pnpm cloudflare:deploy:production
wrangler secret put MURMUR_RELAY_TOKEN_SECRET --config wrangler.staging.jsonc
wrangler secret put MURMUR_PRIVATE_GROUP_SECRET --config wrangler.staging.jsonc
pnpm cloudflare:deploy:staging
```

Credential challenges and account-signed blind issuance are stateless Worker
operations. Proof, token, and canonical-record requests carry the opaque group
header and are routed to that group's Durable Object. Each fresh object stores
only its pinned opaque ID, current encrypted record, opaque member index, and
bounded one-use presentation challenges. There is no legacy private-group
record decoder or Durable Object storage migration path at 0.5.0.

The application server mounts `createRelaySessionFetchHandler`. Its
`authorize` callback authenticates the user, verifies that the signed device
key belongs to that account, and returns the Worker endpoint plus a stable
admission principal. The handler's token secret is server configuration and is
never sent to a client.

The staging deployment is the permanent remote integration target. Run
`pnpm test:staging` from the repository root with
`MURMUR_RELAY_STAGING_TOKEN_SECRET` set to the protected staging capability.
GitHub verifies staging on every non-fork pull request, every `main` push, and
every release before publication.

## SQLite

```bash
pnpm --filter @slopus/murmur-relay build

MURMUR_RELAY_STORE=sqlite \
MURMUR_RELAY_DB=./data/murmur-relay.sqlite \
MURMUR_PRIVATE_GROUP_SECRET=<canonical-32-byte-base64url> \
MURMUR_RELAY_ORIGINS=https://app.example \
pnpm --filter @slopus/murmur-relay start
```

SQLite is appropriate for one relay process. The store uses WAL mode,
foreign-key enforcement, a busy timeout, and bounded write transactions.

## Postgres

```bash
MURMUR_RELAY_STORE=postgres \
MURMUR_RELAY_DB=postgres://user:password@db.example/murmur \
MURMUR_PRIVATE_GROUP_SECRET=<canonical-32-byte-base64url> \
MURMUR_RELAY_ORIGINS=https://app.example \
pnpm --filter @slopus/murmur-relay start
```

Postgres supports multiple relay processes. LISTEN/NOTIFY wakes long polls and
SSE streams across processes; durable reads always come from tables, so
notifications are not data. Write paths serialize through the global
quota/UUID row.

## Upgrades

The Murmur 0.5.0 release line and its fresh relay schema are the compatibility
baseline. The 0.5.0 deployments start empty: pre-0.5.0 client state, wire
formats, SQLite databases, and Postgres schemas are unsupported and have no
migration path. Provision a fresh database when deploying this baseline.

Every schema upgrade after the 0.5.0 baseline must migrate an existing SQLite
database or Postgres schema in place while preserving pending relay data. Do
not introduce a later upgrade that requires operators to delete relay data or
provision a clean database.

After restoring a relay backup, set `MURMUR_RELAY_DECLARE_RESTORED=1` for one
startup so every client can detect the loss.

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
MURMUR_RELAY_INVITATION_ITEMS_PER_REVOCATION_KEY=32
MURMUR_RELAY_GLOBAL_INVITATION_ITEMS=10000
MURMUR_RELAY_GLOBAL_INVITATION_BYTES=67108864
```

Cached bundles are public signed material, not encrypted application data.
They are non-enumerable and addressable only by their 32-byte SHA-256 digest.
Owner-authorized registration and revocation use
`POST /v1/invitations/owned` and `POST /v1/invitations/revoke`; ensure proxies
forward both routes and do not log their bodies or URLs containing digests.
Revocation tombstones retain only public authority metadata until the original
five-minute expiry and count toward item quotas.

The negotiated Cloudflare WebSocket Worker is delivery infrastructure and does
not implement the HTTP invitation cache. Deploying that Worker alone does not
enable invitation revocation. Applications using negotiated delivery must also
configure a compatible `DiscoveryTransport` backed by the standalone HTTP
routes (or equivalent owner-authorized storage) if reset must invalidate cached
invitations.

## Maintenance

The standalone process starts bounded delivery, invitation, and revocation-
tombstone expiration pruning every ten seconds, skips overlapping runs, and
drains within a one-second time budget. Publish and acknowledgement paths also
commit one bounded prune batch before their own transaction, so expired backlog
cannot permanently block quota recovery.

Back up the database as ordinary pending delivery infrastructure. A relay
restore can replay or lose pending ciphertext; application correctness must
remain idempotent and client state remains authoritative.
