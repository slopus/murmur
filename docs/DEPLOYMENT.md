# Deployment

Running a Murmur relay, from a laptop to a public multi-instance service.

The relay is the only thing you deploy. Clients hold all keys and all plaintext,
so a relay operator is not trusted with message content — but is trusted for
availability.

## Local relay

```bash
pnpm --filter @murmur/relay-node build
PORT=8787 node packages/murmur-relay-node/dist/server/main.js
```

| Variable               | Default                      | Purpose                      |
| ---------------------- | ---------------------------- | ---------------------------- |
| `PORT`                 | `8787`                       | Listen port                  |
| `HOST`                 | `0.0.0.0`                    | Bind address                 |
| `MURMUR_RELAY_DB`      | `./data/murmur-relay.sqlite` | SQLite file                  |
| `MURMUR_RELAY_ORIGINS` | `*`                          | Comma-separated CORS origins |

Point clients at it:

```bash
murmur --relay http://127.0.0.1:8787 sign-in --first-name Alice
```

The process prunes topics inactive for 30 days every hour, and shuts down
cleanly on `SIGINT`/`SIGTERM`.

## Single-instance production

One Node process with SQLite in WAL mode is a genuinely capable deployment:
small rows, no joins on the hot path, and a workload dominated by
insert-and-delete. Put it behind TLS, back up the SQLite file, and set
`MURMUR_RELAY_ORIGINS` if browsers connect.

This is the recommended starting point. Do not scale out before you have a
measurement showing you need to.

## Scaling out

Two things must be solved before running more than one instance.

### 1. Cross-instance wakeups

`RelayService` keeps long-poll waiters in an **in-process map**. A publish
handled by instance A cannot wake a client parked on instance B.

This is a **latency** problem, not a correctness one. When a client parks, the
service first re-checks the store (closing the park/arrive race) and caps the
wait at 30 seconds, after which it re-reads. So a naive N-instance deployment
stays correct; realtime just degrades to ~30-second polling.

Sticky routing cannot fix it: the recipient ID lives inside the signed request
body, not the URL, so no L7 proxy can route on it without parsing the protocol.

The fix is a publish/subscribe wake signal. With Postgres, `LISTEN/NOTIFY` is
enough and needs no extra infrastructure:

- Each instance holds one dedicated `LISTEN` connection.
- `publish` and `addSubscription` issue `NOTIFY` with the recipient ID inside
  the same transaction, so wakes fire only on commit.
- On notification, the instance wakes its local waiters.

Because the 30-second timeout is the backstop, a dropped `LISTEN` connection
degrades to polling instead of losing messages. That property is what makes the
design safe. Implementing it requires a small injectable-wake seam in
`RelayService`, which does not exist yet.

### 2. A shared store

`SqliteRelayStore` is single-process. Multiple instances need a shared
`RelayStore`. **No Postgres implementation exists today** — it has to be
written. The interface is 8 methods
([RELAY_API.md](RELAY_API.md#implementing-a-store)); the logic above it is
already host-neutral.

Translating the SQLite schema is mostly mechanical, but four points need care
because the SQLite store relies on `BEGIN IMMEDIATE` serializing everything:

| Method            | Concern                                                                                                                                                                              |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `publish`         | Replace `SELECT` then `INSERT` with `INSERT … ON CONFLICT (id) DO NOTHING RETURNING`, then compare fingerprints on the no-op path to preserve the collision error.                   |
| `putBlob`         | Same read-then-write race, same fix.                                                                                                                                                 |
| `addSubscription` | Backfills deliveries while a concurrent `publish` may be inserting. `UNIQUE (recipient, event_id)` prevents duplicates; verify no event can be _missed_ in the interleaving.         |
| `pull` ordering   | `BIGSERIAL` values are allocated before commit, so a reader can see a gap that later fills. Clients deduplicate and order anyway, but this is no longer SQLite's strict total order. |

Do not copy the SQLite store's `CREATE TABLE IF NOT EXISTS` bootstrap: N
instances starting at once will race on DDL. Use versioned migrations applied
once.

Test a new store with PGlite rather than a mock, per the repository's
no-mocking-what-you-own rule, and run it against the existing SQLite store's
test suite as a conformance suite.

### Target shape

```text
              TLS load balancer
                     │
     ┌───────────────┼───────────────┐
     │               │               │      stateless relay instances
  relay-1        relay-2         relay-3    (each LISTENs for wakes)
     └───────────────┼───────────────┘
                     │
            Postgres primary  ──── NOTIFY fans wakes back out
                     │
              S3 / R2 for blobs
```

Keep Postgres a single primary. The workload is small-row OLTP with heavy
deletes, and `pull` is read-your-writes sensitive, so read replicas will cause
missed deliveries for no benefit.

## Running a public relay

A public relay is an **open write endpoint**. Signature verification proves an
event came from some keypair, and keypairs are free to generate. The relay code
has no quota system.

Before exposing one publicly:

1. **Rate limiting and quotas.** Per-IP and per-identity, on publish and blob
   upload. Nothing in the relay does this today. `maximumWaiters` (10 000) is
   per-process and is not a quota.
2. **Move blobs out of the database.** 64 MiB `bytea` values TOAST badly and
   will wreck WAL volume and backups. Use S3 or R2.

    Note that `getBlob` returns fully buffered bytes and the HTTP layer buffers
    the whole response, so each concurrent download can cost 64 MiB of memory.
    Serving blobs by redirect or stream requires widening the store interface.
    This is the largest change on the list.

3. **Fix pruning for multiple instances.** Every process runs
   `pruneInactiveTopics` hourly, so N instances means N concurrent prunes, and
   the delete cascades across topics, events, and deliveries in one unbounded
   statement. Take a `pg_try_advisory_lock` and delete in batches, or move
   pruning to a single scheduled job.
4. **Add a health endpoint** for load-balancer probes. There is none.
5. **Set `MURMUR_RELAY_ORIGINS`** if you want to restrict browser origins. The
   `*` default is safe for the protocol but you may want it narrower anyway.

## Suggested order of work

1. Postgres `RelayStore`, tested with PGlite against the shared conformance
   suite.
2. Wake seam in `RelayService` plus `LISTEN/NOTIFY`.
3. Advisory-locked batched pruning, and a health endpoint.
4. Rate limiting and quotas — **required before public exposure**.
5. S3/R2 blob backend, which needs the store interface widened.

Steps 1–3 are mechanical. Step 5 touches the transport contract, so decide early
whether a relay may answer a blob `GET` with a redirect.

## Operational notes

- **Backups**: the relay holds only ciphertext, but losing it loses undelivered
  messages. Clients retry from their outbox, so the loss is bounded, not total.
- **Retention**: topics idle for 30 days are pruned. Clients can recreate a
  topic and resume.
- **Metrics**: none built in. Wrap the fetch handler if you need them.
- **Multiple relays**: clients can publish to several relays at once and
  deduplicate on receipt. Running two independent relays is a legitimate
  availability strategy and needs no coordination between them.
