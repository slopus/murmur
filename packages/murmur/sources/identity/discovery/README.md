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
within five minutes.
