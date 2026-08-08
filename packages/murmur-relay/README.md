# `@murmur/relay`

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
- Signed monotonic acknowledgements trim one processed queue prefix.
- A delivery disappears after every reference is acknowledged or it expires.
- Per-recipient, per-sender, and relay-wide item/byte/reference quotas make
  publication all-or-nothing and bound pending storage. Sender reference quota
  charges multicast fanout rather than only ciphertext records.
- Every trusted-ingress principal has an exact outstanding-reference quota.
  References leave that quota when recipients acknowledge or TTL removes them.

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
pnpm --filter @murmur/relay build
MURMUR_RELAY_STORE=sqlite \
MURMUR_RELAY_DB=./data/murmur-relay.sqlite \
MURMUR_RELAY_ORIGINS='https://app.example' \
pnpm --filter @murmur/relay start
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

The queue schema is intentionally incompatible with the former topic relay.
Startup fails when legacy `murmur_relay_*` tables are present; deploy with a
clean SQLite database or Postgres schema rather than retaining old ciphertext.

The standalone process drains expired data every ten seconds in fixed
transactions, continuing for at most one second per tick. It skips overlapping
ticks rather than building an unbounded maintenance queue.

## HTTP API

| Method | Route            | Purpose                                   |
| ------ | ---------------- | ----------------------------------------- |
| `GET`  | `/health`        | Store health                              |
| `POST` | `/v1/deliveries` | Publish one atomic encrypted multicast    |
| `POST` | `/v1/queue/read` | Authenticated queue read or long poll     |
| `POST` | `/v1/queue/ack`  | Authenticated monotonic queue-prefix trim |
