# Crypto implementation

Mechanical recipient-sealed boxes live here. Identity conversion and validation
remain in the public crypto domain; profile, friend, relay, and MLS formats do
not enter this directory.

```text
recipient Ed25519 key -> canonical X25519 point
ephemeral X25519 key  -> DH -> HKDF -> AES-GCM sealed box
recipient root        -> X25519 secret -> open + authenticate
```

The implementation is the narrow cryptographic mechanism beneath the identity
and friend protocols; it does not choose relay destinations or durable state.
