# Discovery

A self-contained signed bundle binds one public Murmur identity to current
one-use MLS KeyPackages. Applications share the bytes out of band or through
their own directory.

```text
identity + current KeyPackages -> signed canonical bundle -> application lookup
verified bundle ------------------------------------------> MLS bootstrap input
```

Discovery creates no relationship, relay record, profile exchange, or channel.
