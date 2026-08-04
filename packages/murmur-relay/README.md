# `@murmur/relay`

Murmur Relay is a deliberately dumb ordered event store. It sees signed opaque
bytes, topic capabilities, expiration times, and collapse keys; it does not know
about identities, contacts, chats, groups, or MLS.

## Topics

A topic is identified by its type, name, and authorization public key(s):

- `Write Topic` requires the designated key for writes and is publicly readable.
- `Read Topic` accepts any correctly signed writer and requires the designated
  key for reads.
- `Read and Write Topic` requires the designated keys in both directions.

One capability key can namespace many independent names. Protected reads use a
short-lived one-use challenge signed by the read key. The secret key never
crosses the relay boundary.

Each topic contains only an ordered event store. A missing `expiresAt` makes an
event durable. Publishing with a `collapseKey` atomically removes older retained
events carrying the same key in that topic. Relay sequences are never reused, so
expiration and collapse create intentional cursor holes.

## Run

```bash
pnpm --filter @murmur/relay build
MURMUR_RELAY_STORE=sqlite \
MURMUR_RELAY_DB=./data/murmur-relay.sqlite \
pnpm --filter @murmur/relay start
```

Set `MURMUR_RELAY_STORE=postgres` and provide a Postgres URL in
`MURMUR_RELAY_DB` for the Postgres backend. Node 22.5 or later is required.

## HTTP API

| Method | Route                 | Purpose                                  |
| ------ | --------------------- | ---------------------------------------- |
| `GET`  | `/health`             | Store health                             |
| `POST` | `/v1/events`          | Publish one signed durable event         |
| `POST` | `/v1/read-challenges` | Issue a one-use protected-read challenge |
| `POST` | `/v1/events/read`     | Read or long-poll ordered events         |

There are no snapshot, list, blob, ephemeral fanout, account, or migration
routes.
