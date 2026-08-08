# Identity discovery

The identity domain now contains discovery only. A discovery bundle is a
strictly encoded, signed, self-contained binding from one public Murmur identity
to current one-use MLS KeyPackages.

```text
identity root -> public identity -> signed discovery bundle
                                \-> MLS credential/signature binding
```

Finding and sharing bundles is application-owned. The relay does not provide a
directory. Session bootstrap consumes the KeyPackage once and retains the local
claim through its full KeyPackage lifetime.
