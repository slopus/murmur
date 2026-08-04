# Relay deployment

The Murmur relay is an ordered opaque event store. It persists signed events,
publish receipts, protected-read challenges, and per-topic heads. It has no
identity registry, application protocol, blob service, or plaintext.

```text
Murmur -- HTTPS --> relay -- SQLite file
                            `-- or PostgreSQL
```

Node 22.5 or later is required for a source build. The release container embeds
the Bun-built relay executable.

## Local process

Build and run a single SQLite-backed relay:

```bash
pnpm --filter @murmur/relay build

MURMUR_RELAY_STORE=sqlite \
MURMUR_RELAY_DB=./data/murmur-relay.sqlite \
pnpm --filter @murmur/relay start
```

The defaults are `sqlite`, `./data/murmur-relay.sqlite`, host `0.0.0.0`, and
port `8787`. The process prunes expired retained events hourly and closes the
HTTP server, wake source, and store on `SIGINT` or `SIGTERM`.

For PostgreSQL, set:

```bash
MURMUR_RELAY_STORE=postgres \
MURMUR_RELAY_DB=postgres://user:password@database/murmur \
pnpm --filter @murmur/relay start
```

PostgreSQL supplies both durable storage and cross-process wake notifications.
SQLite uses in-process wake notifications and therefore supports one relay
process for a database file.

## Configuration

| Variable             | Default                      | Meaning                                  |
| -------------------- | ---------------------------- | ---------------------------------------- |
| `HOST`               | `0.0.0.0`                    | HTTP listen host                         |
| `PORT`               | `8787`                       | HTTP listen port                         |
| `MURMUR_RELAY_STORE` | `sqlite`                     | `sqlite` or `postgres`                   |
| `MURMUR_RELAY_DB`    | `./data/murmur-relay.sqlite` | SQLite path or PostgreSQL connection URL |

Terminate public TLS in front of the relay and preserve request bodies without
rewriting them. The API routes are documented in
[`RELAY_API.md`](RELAY_API.md).

## Container

The release image runs as UID/GID 65532 and stores its default SQLite database
at `/data/murmur-relay.sqlite`:

```bash
docker volume create murmur-relay-data
docker run --detach \
    --name murmur-relay \
    --restart unless-stopped \
    --publish 8787:8787 \
    --volume murmur-relay-data:/data \
    ghcr.io/slopus/murmur-relay:latest
```

The image exposes `/health` for startup, readiness, and liveness probes. A bind
mount must be writable by UID/GID 65532.

## k3s

[`murmur-relay.k3s.yaml`](../murmur-relay.k3s.yaml) runs one SQLite replica with
a `ReadWriteOnce` persistent volume and a `Recreate` strategy:

```bash
kubectl apply -f murmur-relay.k3s.yaml
kubectl rollout status deployment/murmur-relay
```

Pin the manifest image tag and digest to a reviewed release before production.
Use PostgreSQL and a deployment configured with `MURMUR_RELAY_STORE=postgres`
when multiple relay replicas are required.

## Operations

The manifest intentionally creates a ClusterIP service. For a quick local
check:

```bash
kubectl --namespace default port-forward service/murmur-relay 8787:8787
curl http://127.0.0.1:8787/health
```

For public browser or CLI traffic, create a TLS-enabled Ingress resource in the
`default` namespace and point it at the `murmur-relay` Service on port 8787.
The Traefik controller may run in any namespace, but a standard Kubernetes
Ingress cannot reference a Service in a different namespace. Use the
deployment's real hostname and certificate, and do not expose the relay
publicly over plaintext HTTP.

After publishing and deploying a new relay version, run the opt-in external
smoke test:

```bash
pnpm --filter @murmur/relay test:live
```

It targets `https://murmur.cluster-fluster.com` by default and performs only
read-only welcome, health/CORS, and missing-topic checks. Set
`MURMUR_LIVE_RELAY_URL` to exercise another deployment.

SQLite and `local-path` require exactly one replica. Use Postgres plus S3 and a
storage-specific manifest before scaling horizontally. Deleting the
`murmur-relay-data` persistent volume claim deletes relay state.

## Environment

The standalone executable reads these variables from
`packages/murmur-relay/sources/main.ts`.

| Variable                            | Default                      | Meaning                                                                   |
| ----------------------------------- | ---------------------------- | ------------------------------------------------------------------------- |
| `PORT`                              | `8787`                       | TCP listen port, integer 1 through 65,535.                                |
| `HOST`                              | `0.0.0.0`                    | TCP listen host.                                                          |
| `MURMUR_RELAY_STORE`                | `sqlite`                     | Storage backend: `sqlite` or `postgres`.                                  |
| `MURMUR_RELAY_DB`                   | `./data/murmur-relay.sqlite` | SQLite database path; required Postgres connection string for `postgres`. |
| `MURMUR_RELAY_ORIGINS`              | `*`                          | `*` or a comma-separated list of exact HTTP(S) CORS origins.              |
| `MURMUR_RELAY_BLOB_BACKEND`         | `local`                      | Blob backend: `local` or `s3`.                                            |
| `MURMUR_RELAY_BLOB_DIR`             | `./data/blobs`               | Local content-addressed filesystem root.                                  |
| `MURMUR_RELAY_BLOB_SECRET`          | generated per process        | Local signed-link HMAC secret, encoded as UTF-8 and at least 32 bytes.    |
| `MURMUR_RELAY_TRUSTED_PROXIES`      | unset                        | Positive trusted hop count or comma-separated trusted proxy IP list.      |
| `MURMUR_RELAY_S3_ENDPOINT`          | required for `s3`            | S3-compatible HTTP(S) endpoint without credentials, query, or fragment.   |
| `MURMUR_RELAY_S3_REGION`            | required for `s3`            | SigV4 region.                                                             |
| `MURMUR_RELAY_S3_BUCKET`            | required for `s3`            | Bucket name.                                                              |
| `MURMUR_RELAY_S3_ACCESS_KEY_ID`     | required for `s3`            | SigV4 access key ID.                                                      |
| `MURMUR_RELAY_S3_SECRET_ACCESS_KEY` | required for `s3`            | SigV4 secret access key.                                                  |
| `MURMUR_RELAY_S3_PATH_STYLE`        | `false`                      | `true` for path-style S3 URLs, commonly needed by MinIO.                  |

The local blob secret is important. If it is absent, the relay warns and
generates 32 random bytes. Links issued before a restart then stop working, and
other instances reject them. Set one stable secret of at least 32 UTF-8 bytes
for a persistent local deployment. Treat it as a secret.

`MURMUR_RELAY_TRUSTED_PROXIES` is the only setting that permits the relay to
look at `X-Forwarded-For`. Leave it unset for a direct deployment. Configure it
only when the immediate network path is understood; otherwise client-provided
forwarded headers could choose the rate-limit key.

`MURMUR_RELAY_ORIGINS` accepts `*` by itself, or exact origins such as
`https://app.example,http://localhost:3000`. Entries may be separated by
whitespace after commas. Paths, queries, fragments, credentials, trailing
slashes, non-HTTP(S) URLs, empty entries, duplicates, and combining `*` with
another entry are startup errors.

`MURMUR_RELAY_STORE` accepts exactly `sqlite` or `postgres` in lowercase. Any
other value is a startup error; it is not treated as an implicit Postgres
selection.

## Single-instance production

SQLite is the intended single-instance setup:

```text
TLS reverse proxy
        |
        v
one relay process
        |
        +-- SQLite database in WAL mode
        `-- local blob tree, or S3
```

The process creates the parent SQLite directory if needed and enables WAL and
foreign keys. SQLite's store and in-process wake source are single-process
components; do not run multiple processes against the same SQLite deployment.

For a public endpoint, terminate TLS in front of the relay, choose an explicit
`MURMUR_RELAY_ORIGINS` list when browser access should be restricted, preserve
the database and local blob directory with ordinary operational backups, and
monitor process and disk health. Those operational controls are not built into
the package.

Local blobs are sharded by the first four characters of the base64url SHA-256
ID. Uploads stream to a same-directory temporary file, hash during transfer,
and are atomically installed only after the hash matches. This makes local
storage a reasonable simple choice for one process with local persistent disk.

## Multiple instances with Postgres

Choose Postgres for multiple relay processes:

```bash
MURMUR_RELAY_STORE=postgres \
MURMUR_RELAY_DB=postgresql://user:password@postgres.example/murmur \
MURMUR_RELAY_BLOB_BACKEND=s3 \
MURMUR_RELAY_S3_ENDPOINT=https://s3.example \
MURMUR_RELAY_S3_REGION=region \
MURMUR_RELAY_S3_BUCKET=murmur-blobs \
MURMUR_RELAY_S3_ACCESS_KEY_ID=access \
MURMUR_RELAY_S3_SECRET_ACCESS_KEY=secret \
pnpm --filter @murmur/relay start
```

The Postgres store:

- runs versioned migrations under a session advisory lock at startup;
- takes a per-topic transaction advisory lock before publishing, producing
  gapless per-topic sequences;
- emits `pg_notify` in the same publish transaction;
- uses cluster-wide try-locks for event and inactive-topic pruning.

Each process owns a `PostgresWakeSource` with a dedicated reconnecting `LISTEN`
connection. A committed topic wake notifies parked long polls on other
instances. Wakes are only a latency optimization: event reads re-check the
store and timeout after at most 30 seconds, so a lost notification does not
silently lose data.

Use S3 rather than local blobs for this configuration. The local backend keeps
bytes on the filesystem of the particular process and its relative signed links
also require a shared HMAC secret. The S3 backend returns absolute presigned
URLs, so bytes bypass every relay process.

There is an important testing caveat: Postgres behavior is exercised through
PGlite in the test suite. `PgPoolDatabase`, a live PostgreSQL service,
cross-instance `LISTEN`/`NOTIFY`, and advisory-lock contention have not been
tested against a real running Postgres server.

## Blob backend choice

| Backend | Bytes travel through       | Returned link      | Integrity behavior                                                                         | Best fit                                |
| ------- | -------------------------- | ------------------ | ------------------------------------------------------------------------------------------ | --------------------------------------- |
| `local` | Relay process              | Relative relay URL | Streams, hashes while uploading, atomically installs only matching content-addressed bytes | One instance with local persistent disk |
| `s3`    | S3-compatible object store | Absolute SigV4 URL | Upload binds `x-amz-checksum-sha256`; download link follows signed `HEAD` existence check  | Multiple instances or object storage    |

The S3 implementation is verified against the published AWS presigned-GET
example. It has not been tested against a live bucket or MinIO. Treat an S3 or
MinIO deployment as an integration task that still needs its own live test,
including bucket CORS policy for browser clients.

## What is still missing before a public deployment

The code can run a relay, but these gaps remain material:

- There has been no independent security audit. MLS is a tested Murmur RFC 9420
  subset, not a claim of complete MLS interoperability or review.
- Public identity tokens are not verified. There is no safety-number workflow
  and no key transparency, so a machine-in-the-middle on token exchange
  compromises later contact, direct-message, and group security.
- Direct messages have no post-compromise security because they are sealed to
  long-term X25519 identity keys.
- Relay metadata remains visible: topic IDs, relay event author signing keys,
  timing, and sizes.
- The default rate limiter is per process. With `N` instances, its effective
  allowance is approximately `N` times the configured limit. A shared limiter
  must be supplied through `RateLimiter` to change that.
- The SigV4 backend lacks a live S3/MinIO integration test.
- There is no identity key rotation.
- Release automation validates tests, types, lint, formatting, npm packaging,
  and the multi-architecture container build before publication.

Before exposing a public service, also decide how to manage backups, database
credentials, S3 credentials, TLS, reverse-proxy limits, monitoring, incident
response, and retention requirements. Murmur does not provide those operating
procedures.

## Durable operations

- Back up the SQLite file or PostgreSQL database using ordinary database tools.
- Monitor `/health`, HTTP error rates, retained event volume, and disk usage.
- Keep the relay clock synchronized because event creation and expiration
  validation uses Unix milliseconds.
- Preserve publish receipts when pruning expired event bodies; exact retries
  depend on those receipts remaining durable.
- Treat database disclosure as metadata and ciphertext disclosure. Relay
  compromise cannot decrypt Murmur payloads but can affect availability,
  ordering, retention, and traffic analysis.
