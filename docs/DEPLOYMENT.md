# Deployment

The Murmur relay stores opaque signed topic state and serves or issues links for
ciphertext blobs. It does not hold client identity secrets or plaintext, but it
remains an availability and metadata boundary. Run it as a Node process, a
standalone Bun executable, or the published Linux container.

Node 22.5 or later is required for the source build. Bun is embedded in the
standalone executable and release container.

## Local run

Build and start the standalone relay:

```bash
pnpm --filter @murmur/relay build

MURMUR_RELAY_STORE=sqlite \
MURMUR_RELAY_DB=./data/murmur-relay.sqlite \
pnpm --filter @murmur/relay start
```

Defaults are SQLite, `./data/murmur-relay.sqlite`, local blobs in
`./data/blobs`, host `0.0.0.0`, and port `8787`. On startup the process runs a
retention sweep, then repeats it hourly. It closes the HTTP server, blob
backend, wake source, and store on `SIGINT` or `SIGTERM`.

Point the CLI at it:

```bash
murmur sign-in --first-name Alice --relay http://127.0.0.1:8787
```

## Standalone Bun executable

Bun 1.3.6 or later can compile the relay, its JavaScript dependencies, and the
Bun runtime into one platform-specific executable:

```bash
pnpm --filter @murmur/relay build:binary
./packages/murmur-relay/dist/murmur-relay
```

The build-only adapter maps the relay's `node:sqlite` usage onto Bun's embedded
SQLite implementation. It does not change the ordinary Node build. The same
environment variables configure both executables.

To cross-compile, pass one of Bun's compile targets and a distinct output path:

```bash
pnpm --filter @murmur/relay build:binary -- \
    --target bun-linux-x64 \
    --outfile dist/murmur-relay-linux-x64
```

The output embeds Bun and all bundled JavaScript, but it is not a fully
statically linked binary: standard operating-system libraries remain dynamic.
It also does not embed mutable state or configuration. The SQLite database,
local blob directory, Postgres service, S3 service, secrets, and environment
remain external.

## Container image

Every version release publishes a multi-architecture image:

```text
ghcr.io/slopus/murmur-relay:<version>
    +-- linux/amd64
    `-- linux/arm64
```

Run the SQLite and local-blob configuration with a persistent named volume:

```bash
docker volume create murmur-relay-data
docker run --detach \
    --name murmur-relay \
    --restart unless-stopped \
    --publish 8787:8787 \
    --volume murmur-relay-data:/data \
    --env MURMUR_RELAY_BLOB_SECRET="<stable-secret-at-least-32-characters>" \
    ghcr.io/slopus/murmur-relay:latest
```

The image runs as UID/GID 65532 and writes the SQLite database and local blobs
under `/data`. A bind mount must be writable by that identity. The image does
not terminate TLS; put it behind an HTTPS reverse proxy for public access.

## k3s

[`murmur-relay.k3s.yaml`](../murmur-relay.k3s.yaml) deploys the released
multi-architecture image in the `murmur` namespace. It uses k3s's default
`local-path` StorageClass, one 10 GiB persistent volume, one SQLite relay
replica, health probes, resource bounds, and the restricted Pod Security
profile.

Create the namespace and stable blob-link secret once:

```bash
kubectl create namespace murmur --dry-run=client --output=yaml | kubectl apply --filename=-

MURMUR_K3S_BLOB_SECRET="$(openssl rand -base64 48)"
kubectl --namespace murmur create secret generic murmur-relay-secrets \
    --from-literal=blob-secret="$MURMUR_K3S_BLOB_SECRET"
unset MURMUR_K3S_BLOB_SECRET
```

Do not recreate that secret during ordinary upgrades: rotating it immediately
invalidates every outstanding local blob-transfer link. Deploy and wait for
readiness:

```bash
kubectl apply --filename=murmur-relay.k3s.yaml
kubectl --namespace murmur rollout status deployment/murmur-relay
kubectl --namespace murmur get pods,persistentvolumeclaims,services
```

The manifest intentionally creates a ClusterIP service. For a quick local
check:

```bash
kubectl --namespace murmur port-forward service/murmur-relay 8787:8787
curl http://127.0.0.1:8787/health
```

For public browser or CLI traffic, create a TLS-enabled Ingress resource in the
`murmur` namespace and point it at the `murmur-relay` Service on port 8787.
The Traefik controller may run in any namespace, but a standard Kubernetes
Ingress cannot reference a Service in a different namespace. Use the
deployment's real hostname and certificate, and do not expose the relay
publicly over plaintext HTTP.

SQLite and `local-path` require exactly one replica. Use Postgres plus S3 and a
storage-specific manifest before scaling horizontally. Deleting the `murmur`
namespace or its persistent volume claim deletes relay state.

## Environment

The standalone executable reads these variables from
`packages/murmur-relay/sources/main.ts`.

| Variable                            | Default                      | Meaning                                                                   |
| ----------------------------------- | ---------------------------- | ------------------------------------------------------------------------- |
| `PORT`                              | `8787`                       | TCP listen port, integer 1 through 65,535.                                |
| `HOST`                              | `0.0.0.0`                    | TCP listen host.                                                          |
| `MURMUR_RELAY_STORE`                | `sqlite`                     | Storage backend: `sqlite` or `postgres`.                                  |
| `MURMUR_RELAY_DB`                   | `./data/murmur-relay.sqlite` | SQLite database path; required Postgres connection string for `postgres`. |
| `MURMUR_RELAY_ORIGINS`              | `*`                          | `*` or a comma-separated CORS origin list.                                |
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
