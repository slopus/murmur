# Private-group mathematics

This internal module contains the prime-order Ristretto255 machinery used by
private-group credentials and encrypted identifiers. It is deliberately not
re-exported from `sources/index.ts`.

All externally stored values are canonical byte encodings. Secret scalars are
32-byte little-endian `Uint8Array` values, points are RFC 9496 encodings, and
decoders reject alternate or non-canonical representations.

```text
Ristretto points/scalars
          |
          +-- canonical transcripts -- generalized Schnorr
          |
          +-- ElGamal points
          |
          `-- algebraic MAC
```

The generalized Schnorr challenge commits to its domain, statement descriptor,
complete relation (targets and generators), every first-round commitment, and
the caller's external context.

## Structure

- `index.ts` — the export surface documented below.
- `types.ts` — shared interfaces (`ElGamalKeyPair`, `SchnorrRelation`, ...).
- `impl/` — one file per primitive; see `impl/README.md`.
- `tests/` and `impl/tests/` — positive vectors plus forgery, malleability,
  non-canonical-encoding, and cross-domain rejection tests.

## Exports

### Points (`impl/point.ts`)

Every function takes and returns 32-byte canonical Ristretto255 encodings and
throws on anything else.

- `canonicalizePoint(value: Uint8Array): Uint8Array` — decode and re-encode a
  point, rejecting non-canonical bytes. The identity is allowed.
- `canonicalizeNonIdentityPoint(value: Uint8Array): Uint8Array` — same, but
  additionally rejects the identity. Used for public keys, where the identity
  would make every discrete-log statement trivially true.
- `identityPoint(): Uint8Array` — the group identity (the "zero" point).
- `basePoint(): Uint8Array` — the standard Ristretto255 generator `G`.
- `hashToPoint(domain: string, parts: readonly Uint8Array[]): Uint8Array` —
  derive an independent generator by hashing labeled input to the curve.
  Distinct domains give unrelated generators with unknown discrete logs.
- `addPoints(...values): Uint8Array` / `subtractPoints(left, right)` — group
  addition and subtraction.
- `multiplyPoint(point, scalar): Uint8Array` — scalar multiplication `s·P`.
- `multiplyBase(scalar): Uint8Array` — `s·G`, the usual "public key from
  secret" operation.
- `equalPoints(left, right): boolean` — canonical equality.
- `encodeBytesToPoint(value: Uint8Array): Uint8Array` — reversibly embed at
  most 16 bytes of application data into a point so it can be ElGamal
  encrypted. Only points produced by this function can be decoded back.
- `decodePointToBytes(point: Uint8Array): Uint8Array` — recover the embedded
  bytes from an `encodeBytesToPoint` result.
- `encodePointVector(points: readonly Uint8Array[]): Uint8Array` — canonical
  length-prefixed concatenation, used inside transcripts and codecs.

### Scalars (`impl/scalar.ts`)

Scalars are field elements modulo the group order; they are the "secret
numbers" of every construction here.

- `RISTRETTO_ORDER: bigint` — the prime group order `ℓ`.
- `decodeScalar(value: Uint8Array, allowZero = true): bigint` — strict decode;
  rejects out-of-range bytes, and zero when `allowZero` is false.
- `encodeScalar(value: bigint): Uint8Array` — canonical 32-byte encoding.
- `reduceScalar(value: Uint8Array): Uint8Array` — reduce wide input mod `ℓ`.
- `hashToScalar(domain, parts, nonzero = false): Uint8Array` — deterministic
  domain-separated hash to a scalar; the Fiat-Shamir challenge builder.
- `randomScalar(): Uint8Array` — uniform nonzero random scalar.
- `addScalars(...values)` / `multiplyScalars(...values)` /
  `negateScalar(value)` — arithmetic mod `ℓ`.
- `encodeScalarVector(values): Uint8Array` — canonical length-prefixed
  concatenation for transcripts.

### Transcript (`impl/transcript.ts`)

- `encodeTranscript(domain: string, fields: readonly TranscriptField[]):
Uint8Array` — the one canonical transcript encoder. Every field is a
  `{ label, value }` pair; labels and lengths are framed so no two distinct
  field sequences can collide into the same byte stream. Everything hashed by
  the Schnorr and credential layers goes through this function.

### ElGamal over points (`impl/elgamal.ts`)

Additive ElGamal on Ristretto points: `C1 = rG`, `C2 = M + r·PK`, decryption
computes `M = C2 − sk·C1`. This is the encryption behind deterministic member
identifiers.

- `generateElGamalKeyPair(): ElGamalKeyPair` — random key pair.
- `deriveElGamalKeyPair(seed: Uint8Array, domain: string): ElGamalKeyPair` —
  deterministic key pair from a seed, used to derive per-group keys from the
  group master secret.
- `validateElGamalKeyPair(keyPair): void` — throws unless the pair is
  canonical and consistent.
- `encryptElGamalPoint(publicKey, message, randomness?): ElGamalCiphertext` —
  encrypt a point; passing explicit `randomness` makes the ciphertext
  deterministic (how the same account always produces the same in-group UID).
- `decryptElGamalPoint(secretKey, ciphertext): Uint8Array` — recover `M`.
- `encodeElGamalCiphertext(ciphertext)` / `decodeElGamalCiphertext(value)` —
  strict 68-byte wire codec.
- `destroyElGamalKeyPair(keyPair): void` — zero the secret in place.

### Algebraic MAC (`impl/algebraicMac.ts`)

A CPZ-style keyed-verification MAC over two group elements (hidden account
identifier and expiry). It is the core of the anonymous credential: only the
issuer can verify it, but holders can prove possession in zero knowledge.

- `issueAlgebraicMac(parameters, key, identifierPoint, expiryPoint, tInput?):
AlgebraicMac` — issue `(t, U, V)` with `V = U·(w + x0 + x1·t)`-style keyed
  combination over the attribute points.
- `verifyAlgebraicMac(parameters, key, identifierPoint, expiryPoint, mac):
boolean` — issuer-side check; constant-time on the deciding comparison.
- `unblindAlgebraicMac(mac, blinding, unblindingKey): AlgebraicMac` — remove
  the client's blinding after blind issuance so the credential is usable.
- `encodeAlgebraicMac(mac)` / `decodeAlgebraicMac(value)` — strict codec.
- `destroyAlgebraicMacKey(key): void` — zero all five secret scalars.

### Generalized Schnorr proofs (`impl/schnorr.ts`)

Zero-knowledge proofs of knowledge for any system of linear relations
`target = Σ generator·witness`. Statements are described with
`SchnorrRelation`/`SchnorrTerm` and proved with Fiat-Shamir.

- `proveGeneralizedSchnorr(options: SchnorrProveOptions): Uint8Array` — prove
  knowledge of `witnesses` satisfying `relations`; the challenge binds
  `domain`, `statement`, the full relations, every first-round commitment,
  and `context`.
- `verifyGeneralizedSchnorr(options: SchnorrVerifyOptions): boolean` —
  recompute and check the challenge; rejects a proof whose transcript differs
  in any bound component.
- `encodeSchnorrProof(commitments, responses)` /
  `decodeSchnorrProof(value, witnessCount)` — length-checked codec.
- `reconstructSchnorrCommitment(relation, responses, challenge)` — rebuild
  one implied first-round commitment from a response; used by verification
  and by higher layers that fold proofs together.

### Byte codec helpers (`impl/codec.ts`)

Small canonical building blocks shared by every encoder above:
`encodeUint16` / `decodeUint16`, `encodeUint32`, `encodeUint64` /
`decodeUint64`, `lengthPrefix(value)`, and `protocolLabel(value)` (a framed
UTF-8 domain label).

### Types (`types.ts`)

`ElGamalKeyPair`, `ElGamalCiphertext`, `SchnorrTerm`, `SchnorrRelation`,
`SchnorrProveOptions`, `SchnorrVerifyOptions`, `AlgebraicMacSecretKey`,
`AlgebraicMacParameters`, `AlgebraicMac`.

## Security status

This is new custom cryptographic code. The master plan requires independent
review and external audit before any production reliance.
