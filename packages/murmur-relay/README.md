# `@murmur/relay`

Murmur Relay is a deliberately dumb Node relay for opaque, signed ciphertext.
It authenticates relay events and stores topic state without knowing whether the
bytes represent messages, documents, profiles, or anything else. Node 22.5 or
later is required.

## Topic model

Each topic has an optional snapshot, an ordered list, and a bounded event log.
Every accepted event gets a gapless topic sequence and may atomically mutate the
snapshot and list.

```text
signed event
    |
    v
+---------------- opaque topic ----------------+
| snapshot?       ordered list       event log |
| current bytes   current elements   retained  |
| permanent*      permanent*         ~7 days   |
+-----------------------------------------------+
    |                  |
    +------ blobs -----+  content-addressed, permanent

* until the whole topic is removed for inactivity (30 days by default)
```

Snapshot and list writes use optimistic versions. For snapshots,
`expectedVersion: 0` means that no snapshot is present; recreating a deleted
snapshot succeeds but receives the next monotonic generation. List operations
append, replace, or delete opaque elements. A durable event receipt makes
identical retries return the original sequence even after the retained event
body has expired; reusing an event ID for different signed content returns a
conflict.

## Run the standalone server

Build once, then select SQLite or Postgres through environment variables:

```bash
pnpm --filter @murmur/relay build

# SQLite (these are the defaults)
MURMUR_RELAY_STORE=sqlite \
MURMUR_RELAY_DB=./data/murmur-relay.sqlite \
pnpm --filter @murmur/relay start

# Postgres
MURMUR_RELAY_STORE=postgres \
MURMUR_RELAY_DB=postgresql://user:password@localhost/murmur \
pnpm --filter @murmur/relay start
```

The Postgres host uses a pool for storage and a dedicated `LISTEN` connection
for cross-process long-poll wakeups. Migrations run automatically under a
Postgres advisory lock. SQLite uses `node:sqlite`, WAL, and one process-local
wake source.

The executable reads:

| Variable               | Default                      | Meaning                                       |
| ---------------------- | ---------------------------- | --------------------------------------------- |
| `MURMUR_RELAY_STORE`   | `sqlite`                     | `sqlite` or `postgres`                        |
| `MURMUR_RELAY_DB`      | `./data/murmur-relay.sqlite` | SQLite path; required Postgres connection URL |
| `MURMUR_RELAY_ORIGINS` | `*`                          | `*` or comma-separated CORS origins           |
| `HOST`                 | `0.0.0.0`                    | Listen address                                |
| `PORT`                 | `8787`                       | Listen port                                   |

Embedders can compose the same pieces directly:

```ts
import {
    InProcessWakeSource,
    RelayService,
    SqliteRelayStore,
    createNodeRelayServer,
    createRelayFetchHandler,
} from "@murmur/relay";

const service = new RelayService(
    new SqliteRelayStore("./data/murmur-relay.sqlite"),
    {},
    new InProcessWakeSource(),
);
const server = createNodeRelayServer(createRelayFetchHandler(service));
server.listen(8787, "127.0.0.1");
```

For Postgres, wrap a `pg.Pool` in `PgPoolDatabase`, create the store with
`PostgresRelayStore.create`, and pass a `PostgresWakeSource` to `RelayService`.

## HTTP API

All event and state bytes are unpadded base64url in JSON. Sequence and version
bigints are decimal strings.

| Method and route                                       | Behavior                                                      |
| ------------------------------------------------------ | ------------------------------------------------------------- |
| `GET /health`                                          | Check backing-store health                                    |
| `POST /v1/topics/:topic/events`                        | Validate, authenticate, and atomically publish a signed event |
| `GET /v1/topics/:topic/state?limit=N`                  | Read the topic head, snapshot, and first list page            |
| `GET /v1/topics/:topic/list?cursor=C&limit=N`          | Continue the ordered current list                             |
| `GET /v1/topics/:topic/events?since=S&limit=N&wait=MS` | Read retained events; optionally long-poll up to 30 seconds   |
| `PUT /v1/blobs/:sha256`                                | Store raw ciphertext under its base64url SHA-256 ID           |
| `GET /v1/blobs/:sha256`                                | Download raw ciphertext                                       |
| `OPTIONS /*`                                           | CORS preflight                                                |

JSON request bodies, individual payloads, snapshots, list elements, operation
counts, blobs, list capacity, page counts, page response bytes, and concurrent
long polls all have configurable bounds. Encoded event/list responses default
to an 8 MiB page budget. A page always includes at least one item when one is
available, even if that single item exceeds the aggregate budget, so pagination
cannot stall.

## Retention and reset

The standalone process sweeps retention hourly. Event bodies are kept for seven
days by default; successful event receipts remain with the topic so retries stay
idempotent. A topic with no successful publish for thirty days is deleted,
including its snapshot, list, retained events, and receipts. Blobs are
independent and are not removed by these sweeps.

Clients must treat cursors as follows:

1. Load `state`, including its `seq`, and paginate `list` until `nextCursor` is
   `null`.
2. Read events after the last applied sequence. If `reset` is `true`, the cursor
   is outside usable history (too old or beyond the topic head); discard
   incremental state and load `state` again.
3. Event pages report the current topic head in top-level `seq`. If the last
   returned event sequence is below that value, request another page using that
   event sequence as `since`. Only an empty page at the known head means caught
   up.
4. Continue list pages whenever `nextCursor` is non-null, even when a page is
   shorter than the requested item count.

The relay promises durable state and idempotent publication, not delivery or
application-level acknowledgement.
