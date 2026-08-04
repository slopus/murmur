# Cipher suite

MLS cipher suite `0x0001`:

- HPKE: DHKEM(X25519, HKDF-SHA-256), HKDF-SHA-256, AES-128-GCM
- Hash: SHA-256
- Signature: Ed25519

HPKE setup follows RFC 9180 base mode. MLS labels use the mandatory
`"MLS 1.0 "` prefix from RFC 9420.

```text
suite 0x0001
  +-- X25519 HPKE ----> KeyPackage, Welcome, UpdatePath
  +-- HKDF-SHA-256 ---> MLS labeled key schedule
  +-- AES-128-GCM ----> HPKE and content protection
  `-- Ed25519 --------> LeafNode, Commit, application signatures
```

Every MLS domain imports this suite profile rather than choosing algorithms
independently.
