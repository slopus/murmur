# Crypto tests

Tests cover the one-root/one-public-key shape, deterministic Ed25519-to-X25519
conversion, symmetric key agreement, signatures, sealed-box recipient
confidentiality, mismatched-root rejection, strict Ed25519 verification, and
secret destruction. Storage tests reject the former independent-secret shape.

```text
root/key validation -> sign + verify -> Ed25519/X25519 conversion
                                      -> seal + open
                                      -> tamper/mismatch rejection
                                      -> zeroization assertions
```

These tests pin the primitive invariants before session bootstrap or MLS state
machines consume the keys.
