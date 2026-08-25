# Private-group state service

This module stores one canonical encrypted record per opaque group identifier.
It sees only group capabilities, deterministic encrypted member entries, fixed
roles, revisions, sizes, and access timing.

```text
authenticated account -> blind credential issuance authority
                                      |
opaque entry -> randomized proof -> short-lived scoped token
                                      |
                               SQLite canonical record
```

The service receives cryptographic issuance and presentation verification as a
narrow authority. It never receives a group master secret or plaintext account
roster. Production HTTP integration must supply the authenticated account
identifier from the authenticated session, never from an unauthenticated
request field.

Tokens contain no account identifier and are scoped to one opaque group,
encrypted entry, fixed role, and expiry. SQLite stores only the current record,
so storage remains bounded by explicit group, member, record-byte, and pending
challenge limits.

This feature requires external cryptographic review before production use. It
hides the persistent social graph from this service, not IP, timing, volume,
cardinality, role, or record-size metadata.

## Structure

- `index.ts` — `PrivateGroupStateService` and the export surface below.
- `types.ts` — store, authority, challenge, and limit interfaces.
- `impl/privateGroupStateStoreSqlite.ts` — the bounded SQLite store.
- `tests/` — service tests against `SqlitePrivateGroupStateStore(":memory:")`.

## Exports

### `class PrivateGroupStateService`

The whole service behavior behind one class; storage and cryptography are
injected so this module never imports browser-library internals.

- `constructor(options: PrivateGroupStateServiceOptions)` — takes a
  `PrivateGroupStateStore`, a `PrivateGroupCredentialAuthority` (byte-only
  issuance/verification adapter), an HMAC token secret, optional limits and
  lifetimes, and a clock.
- `credentialIssuanceContext(authenticationContext: Uint8Array): Uint8Array`
  — derive the domain-separated context a client must bind into its blind
  issuance request, tying issuance to the upstream authenticated session.
- `issueCredential(options): Promise<Uint8Array>` — blind-issue one
  short-lived credential over the hidden identifier of an
  already-authenticated account. The `authenticatedAccountIdentifier` must
  come from upstream authentication, never from the request payload.
- `createPresentationChallenge(options):
Promise<PrivateGroupPresentationChallenge>` — mint one bounded, one-use,
  30-second challenge naming the opaque group, entry, role, and operation.
- `authenticatePresentation(options): Promise<{ bytes, expiresAt }>` —
  atomically consume the challenge, verify the randomized presentation
  against the stored entry and group public parameters, and return a
  short-lived HMAC bearer token scoped to group + entry + role + expiry.
  Replay of a consumed challenge fails.
- `createRecord(options)` — validate and store revision 1 of a group under a
  `create`-scoped token; duplicate groups and oversized records are rejected.
- `readRecord(options)` — return the current canonical record and its hash
  under any valid token for that group.
- `replaceRecord(options)` — atomically replace the record only when the
  caller's expected parent hash matches the stored revision (stale forks are
  rejected) and the token's role permits mutation.
- `close(): void` — release the store.

### Store (`impl/privateGroupStateStoreSqlite.ts`)

- `class SqlitePrivateGroupStateStore` — `node:sqlite` implementation of
  `PrivateGroupStateStore`: current-record-only storage with an entry index
  for duplicate detection, bounded pending challenges, and atomic
  expected-parent replacement. Accepts `":memory:"` for tests.
- `SqlitePrivateGroupStateStoreOptions` — its configuration type.

### Types (`types.ts`)

`PrivateGroupStateStore` (the storage contract),
`PrivateGroupCredentialAuthority` (the injected crypto contract),
`PrivateGroupStateServiceOptions`, `PrivateGroupStateLimits`,
`PrivateGroupStateRecord`, `StoredPrivateGroupStateRecord`,
`PrivateGroupMemberEntry`, `PrivateGroupRole`,
`PrivateGroupPresentationChallenge`, `PrivateGroupChallengeOperation`,
`PrivateGroupAccessToken`.
