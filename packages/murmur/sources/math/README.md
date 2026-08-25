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
