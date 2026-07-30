# Cipher suite

MLS cipher suite `0x0001`:

- HPKE: DHKEM(X25519, HKDF-SHA-256), HKDF-SHA-256, AES-128-GCM
- Hash: SHA-256
- Signature: Ed25519

HPKE setup follows RFC 9180 base mode. MLS labels use the mandatory
`"MLS 1.0 "` prefix from RFC 9420.
