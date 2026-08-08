# Identity discovery

The identity domain now contains discovery only. A discovery bundle is a
strictly encoded, signed, self-contained binding from one public Murmur identity
to current one-use MLS KeyPackages.

```text
identity root -> public identity -> signed discovery bundle
                                \-> MLS credential/signature binding
```

The default path uploads exact signed bytes to the relay's non-enumerable
five-minute cache and shares only their 32-byte SHA-256 digest. The relay does
not provide a directory or identity lookup. Session bootstrap consumes the
private KeyPackage; expiry removes it locally, while a creator retains the
one-use claim through the public KeyPackage's full lifetime.
