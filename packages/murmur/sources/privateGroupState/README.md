# Private-group state client

This internal module is the sole composition boundary between anonymous
private-group credentials and account-aware MLS sessions. It is deliberately
not re-exported from the published package entry point.

```text
MurmurSession.members (logical accounts)
                 |
group master secret -> deterministic encrypted entries -> canonical record
                 |                                      |
                 `-> encrypted attributes + MLS digest  `-> state service
```

Each device supplies the stable `MurmurClient.accountKey`, so every device of
one account reconstructs the same logical entry while remaining an independent
MLS leaf. The client checks that the canonical encrypted roster is exactly the
set of logical accounts in the authenticated MLS session snapshot. It rejects
unauthenticated records, revision forks, rollbacks, gaps, and membership
changes without matching MLS state.

The state service learns opaque identifiers, entry ciphertexts, fixed roles,
revision metadata, cardinality, timing, and sizes. It does not receive group
secrets, account keys, MLS session identifiers, or plaintext attributes. This
does not provide network anonymity. The credential and proof construction
requires external cryptographic audit before production use.

## Structure

- `index.ts` — the export surface documented below.
- `types.ts` — record, token, challenge, and transport interfaces.
- `impl/privateGroupStateClient.ts` — the member-side client.
- `impl/recordCodec.ts` — canonical record construction and verification.
- `impl/credentialAuthority.ts` — byte-only crypto adapter handed to the
  service so the relay never imports library internals.
- `tests/` — end-to-end tests against the real SQLite-backed service.

## Exports

### Client (`impl/privateGroupStateClient.ts`)

- `class PrivateGroupStateClient` — one member's view of one private group,
  constructed from the group master secret, the local account identifier, and
  a `PrivateGroupStateTransport` to the service.
    - `obtainCredential(...): Promise<PrivateGroupAccountCredential>` — run
      blind issuance against the service: the service authenticates the account
      upstream, signs the hidden identifier plus expiry, and the client unblinds
      and validates the result.
    - `createPresentation(...): Uint8Array` — answer one service challenge with
      a randomized zero-knowledge presentation proving the credential covers
      the same hidden identifier as the member's encrypted entry.
    - `authorize(...): Promise<PrivateGroupAccessToken>` — full challenge →
      presentation → short-lived scoped token round trip.
    - `buildInitialRecord(content: PrivateGroupRecordContent):
PrivateGroupStateRecord` — revision 1 from the current authenticated MLS
      snapshot: deterministic member entries, encrypted attributes, MLS digest,
      member-keyed revision authenticator.
    - `buildSuccessorRecord(...): PrivateGroupStateRecord` — next revision
      chained to the accepted parent hash.
    - `acceptRecord(...): PrivateGroupAcceptedState` — the trust gate: verify
      authenticator, decrypt attributes, check revision continuity against the
      trusted tip (no forks, rollbacks, or gaps), and require the encrypted
      roster to equal the logical accounts of the local MLS session snapshot.
    - `createGroup(...)` / `readGroup(...)` / `replaceGroup(...):
Promise<PrivateGroupAcceptedState>` — token-authorized service round
      trips that end in `acceptRecord`.
    - `close(): void` — zero retained group and credential secrets.

### Record codec (`impl/recordCodec.ts`)

- `createPrivateGroupStateRecord(options)` — assemble and authenticate one
  canonical record (encrypts attributes with the group metadata keys, embeds
  the MLS digest, computes the member-keyed revision authenticator).
- `openPrivateGroupStateRecord(options)` — verify and decrypt one record;
  throws on any authenticator or binding mismatch.
- `canonicalMemberEntries(...)` — deterministic sorted encrypted entries for
  a set of logical accounts and roles; both build and accept use it, which is
  what makes "roster equals MLS membership" checkable.
- `encodePrivateGroupStateRecord(record)` /
  `encodeUnsignedPrivateGroupStateRecord(record)` — canonical byte forms
  (signed and pre-authentication).
- `privateGroupStateRecordHash(record): Uint8Array` — the revision hash used
  for parent links and fork detection.
- `privateGroupMlsStateDigest(content): Uint8Array` — hash of the
  authenticated session snapshot (session ID, descriptor, logical members,
  committer) that ties a revision to real MLS state.

### Credential authority adapter (`impl/credentialAuthority.ts`)

- `createPrivateGroupCredentialAuthority(...):
PrivateGroupCredentialAuthorityAdapter` — wraps the `privateGroups` issuer
  into a byte-only interface (`issueCredential`,
  `validateGroupPublicParameters`, `verifyPresentation`) that the relay-side
  service consumes without importing any library internals.

### Types (`types.ts`)

`PrivateGroupRole`, `PrivateGroupMemberEntry`, `PrivateGroupStateRecord`,
`StoredPrivateGroupStateRecord`, `PrivateGroupAccountRole`,
`PrivateGroupPresentationChallenge`, `PrivateGroupAccessToken`,
`PrivateGroupAccountCredential`, `PrivateGroupRecordContent`,
`PrivateGroupAcceptedState`, `PrivateGroupStateClientOptions`,
`PrivateGroupStateTransport`.

## Layering rule

`accounts`/`sessions` and `math`/`privateGroups` never import each other; this
module is their only meeting point. Keep it that way.
