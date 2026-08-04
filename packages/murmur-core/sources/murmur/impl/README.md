# Murmur facade internals

The implementation directory contains strict durable/control codecs and the
mechanical state helpers used by the facade.

```text
facade
  +-- control codec
  +-- durable state codec
  `-- topic/address helpers
```

All codecs are bounded and reject unknown fields. Secret-bearing records remain
inside application-provided persistence.
