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

- Back up the SQLite file or PostgreSQL database using ordinary database tools.
- Monitor `/health`, HTTP error rates, retained event volume, and disk usage.
- Keep the relay clock synchronized because event creation and expiration
  validation uses Unix milliseconds.
- Preserve publish receipts when pruning expired event bodies; exact retries
  depend on those receipts remaining durable.
- Treat database disclosure as metadata and ciphertext disclosure. Relay
  compromise cannot decrypt Murmur payloads but can affect availability,
  ordering, retention, and traffic analysis.
