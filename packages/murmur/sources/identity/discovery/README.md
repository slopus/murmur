# Discovery

A self-contained signed bundle binds one public Murmur identity to current
one-use MLS KeyPackages. The default five-minute flow stores exact public bytes
at the relay and shares only their 32-byte SHA-256 digest.

```text
identity + current KeyPackages -> signed canonical bundle -> relay cache
32-byte digest -> download + hash/signature/expiry checks -> MLS bootstrap
```

Discovery creates no relationship, directory entry, profile exchange, or
channel. Cache records are opaque, non-enumerable, quota-bounded, and expire
within five minutes. Capability security comes from the signed bundle's
high-entropy contents; SHA-256 verifies the exact fetched bytes and does not by
itself make a guessable input secret.

HTTP invitations are bound to a second durable Ed25519 revocation authority.
The invitation identity signs the exact digest/expiry/public-authority tuple;
the private revocation root and digest-to-private-KeyPackage mapping remain in
the creator's store. Single and identity-wide revocation destroy local one-use
state before making an idempotent signed relay request. A failed request stays
pending across restart, but an unreachable relay may keep serving the public
bundle until retry or expiry.
