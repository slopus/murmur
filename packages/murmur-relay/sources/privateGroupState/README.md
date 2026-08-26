# Private-group state service

This experimental module stores one canonical encrypted record per opaque
group identifier. It sees only group capabilities, deterministic encrypted
member entries, fixed roles, revision metadata, sizes, and access timing.

```text
authenticated account -> blind credential issuance authority
                                      |
opaque entry -> randomized proof -> short-lived scoped token
                                      |
                         canonical record store
                         (SQLite / Postgres / Durable Object)
```

The service never receives a group master secret, plaintext account roster,
session identifier, or attributes. Tokens contain no account identifier and
are scoped to one opaque group, encrypted entry, fixed role, and expiry. The
current record persists while the group exists; stores retain no history.

Every accepted write receives a monotonic server-assigned UUIDv7 canonical
version and names its predecessor. An exact create or replacement retry returns
the original accepted result. Stale or conflicting writes fail closed.

## Structure

- `index.ts` — service behavior, secret-based construction, and exports.
- `types.ts` — store, authority, challenge, record, and limit interfaces.
- `http.ts` — strict fetch-compatible credential, proof, and record routes.
- `impl/privateGroupStateStoreSqlite.ts` — bounded SQLite store.
- `impl/privateGroupStateStorePostgres.ts` — Postgres/PGlite store.
- `tests/` — real PGlite store coverage; the browser package runs the complete
  client/service flow against real in-memory SQLite and HTTP handlers.

## Public relay-host construction

- `PrivateGroupStateService` — validates credentials, proofs, tokens, records,
  role authorization, and canonical predecessor replacement.
- `SqlitePrivateGroupStateStore` — synchronous SQLite implementation.
- `PostgresPrivateGroupStateStore.create(database)` — async Postgres/PGlite
  implementation with one clean beta schema and no migration path.
- `createPrivateGroupCredentialAuthorityFromSecret(secret)` — experimental
  trusted-relay authority construction from one 32-byte issuer secret.
- `createPrivateGroupStateServiceFromSecret(options)` — derives independent
  credential-authority and bearer-token domains from one 32-byte deployment
  secret, then constructs the complete service.
- `createPrivateGroupStateFetchHandler(service)` — mounts strict
  `/v1/private-groups/*` routes for configuration, account-signed credential
  issuance, challenges, presentations, and record create/read/replace. Blind
  issuance requires an Ed25519 signature from the named account identity over
  a short-lived server challenge and the exact blind request/context hashes.

## Beta security gaps

- Access tokens are bearer capabilities without proof of possession.
- `commitEventId` is null; server verification of the winning MLS Commit is
  deferred. Clients still enforce the encrypted revision and canonical
  predecessor chains locally.
- The anonymous credential construction requires external cryptographic audit.

The service hides the persistent social graph from storage operators. It does
not hide IP address, timing, volume, cardinality, role, or record-size metadata.
