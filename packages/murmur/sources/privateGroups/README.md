# Private-group identifiers and credentials

This internal domain composes the generic `math` module into the private-group
protocol from the master plan. It is not exported by the published package
entry point.

```text
group master secret
        |
        +--> opaque group id
        +--> deterministic UID ElGamal parameters
        +--> metadata keys
        `--> group proof parameters

authenticated account -- blind request --> credential issuer
        |                                     |
        `----------- unblinded MAC <----------'
                         |
encrypted UID -------- same-id presentation --------> keyed verifier
```

Presentations reveal only the credential expiry and group-specific encrypted
entry. A fresh randomizer hides the issuance transcript. The Fiat-Shamir
context includes the opaque group, encrypted entry, expiry, replay nonce, and
caller-supplied operation context.

## Structure

- `index.ts` — the export surface documented below.
- `types.ts` — parameter, credential, and presentation interfaces.
- `impl/` — one file per concern; see `impl/README.md`.
- `tests/` and `impl/tests/` — round-trip, forgery, cross-group-linkage,
  expiry, and replay rejection tests.

## Exports

### Parameter derivation (`impl/parameters.ts`)

Everything a group needs is derived from one random 32-byte master secret
known only to members; the service only ever sees the public halves.

- `derivePrivateGroupParameters(masterSecret: Uint8Array):
PrivateGroupParameters` — derive the opaque group identifier, the
  group-specific deterministic UID encryption key pair, metadata keys, and
  proof generators. The same account is unlinkable across groups because each
  group derives unrelated parameters.
- `privateGroupPublicParameters(parameters): PrivateGroupPublicParameters` —
  strip secrets, producing what may be given to the state service.
- `deriveCredentialIssuer(masterSecret: Uint8Array): CredentialIssuer` — the
  issuer/verifier secret (algebraic-MAC key plus generators). In production
  this belongs to the service side, seeded by service secrets.
- `accountIdentifierScalar(accountIdentifier: Uint8Array): Uint8Array` — map
  a stable 32-byte account identifier to the hidden credential scalar.
- `credentialIdentifierPoint(...)` / `credentialExpiryPoint(...)` /
  `credentialExpiryScalar(expiresAt: number)` — the attribute group elements
  the MAC signs.
- `destroyPrivateGroupParameters(parameters)` /
  `destroyCredentialIssuer(issuer)` — zero the contained secrets.

### Encrypted UIDs (`impl/uid.ts`)

A member entry is the deterministic ElGamal encryption of the account
identifier point under group-specific parameters: identical within one group
(duplicates detectable, self-reconstructable), unlinkable across groups.

- `deterministicUidRandomness(...)` — derive the fixed encryption randomness
  from the group parameters and account identifier; determinism lives here.
- `createEncryptedUid(parameters, accountIdentifier): EncryptedUid` — build
  the member entry for an account in this group.
- `decryptEncryptedUid(parameters, encryptedUid): Uint8Array` — member-side
  decryption back to the identifier point.
- `isEncryptedUidForAccount(parameters, encryptedUid, accountIdentifier):
boolean` — reconstruct-and-compare, used to find one's own entry.
- `equalEncryptedUids(left, right): boolean` — canonical equality.
- `encodeEncryptedUid(encryptedUid)` / `decodeEncryptedUid(value)` — strict
  codec.
- `validatePrivateGroupPublicParameters(value)` — service-side sanity check
  before storing or verifying against supplied group parameters.

### Blind credential issuance (`impl/credentials.ts`)

The account proves who it is to the service once, then receives a short-lived
credential over its _hidden_ identifier: the service signs without seeing the
identifier, and later cannot link issuance to use.

- `createCredentialIssuanceRequest(...): { request, state }` — client blinds
  its identifier and proves the blinding is well-formed.
- `issueCredential(options): CredentialIssuanceResponse` — issuer verifies the
  request proof and MACs the blinded attributes with an issuance proof of its
  own key.
- `finalizeCredentialIssuance(options): AccountCredential` — client verifies
  the issuer proof and unblinds the MAC into a usable credential.
- `verifyAccountCredential(...)` — keyed check that a finished credential is
  valid and unexpired (issuer side, e.g. in tests).
- `destroyCredentialIssuanceState(state)` — zero retained blinding secrets.

### Presentations (`impl/presentation.ts`)

The zero-knowledge heart: prove "my valid, unexpired credential covers the
same hidden identifier as this encrypted member entry" without revealing the
identifier or making two presentations linkable.

- `createUidPresentation(options): UidPresentation` — randomize the credential
  and produce one generalized Schnorr proof tying credential, encrypted UID,
  expiry, replay nonce, and operation context together.
- `verifyUidPresentation(options): boolean` — service-side verification with
  the issuer key and the group public parameters; rejects expired
  credentials, wrong groups, wrong entries, and replayed or re-contexted
  proofs.

### Wire codecs (`impl/codec.ts`)

Strict canonical encoders/decoders for every boundary artifact:
`encodeCredentialIssuanceRequest` / `decodeCredentialIssuanceRequest`,
`encodeCredentialIssuanceResponse` / `decodeCredentialIssuanceResponse`,
`encodeAccountCredential` / `decodeAccountCredential`,
`encodeUidPresentation` / `decodeUidPresentation`,
`encodePrivateGroupPublicParameters` / `decodePrivateGroupPublicParameters`,
`encodeCredentialIssuerPublicParameters` /
`decodeCredentialIssuerPublicParameters`. Decoders reject non-canonical
bytes; re-encoding always reproduces the input.

### Types (`types.ts`)

`PrivateGroupParameters`, `PrivateGroupPublicParameters`,
`PrivateGroupProofParameters`, `PrivateGroupMetadataKeys`,
`IdentifierEncryptionParameters`, `EncryptedUid`, `CredentialIssuer`,
`CredentialIssuerPublicParameters`, `CredentialIssuanceRequest`,
`CredentialIssuanceResponse`, `CredentialIssuanceState`, `AccountCredential`,
`UidPresentation`.

## Security status

New custom credential and proof protocol code; external cryptographic audit is
required before production use.
