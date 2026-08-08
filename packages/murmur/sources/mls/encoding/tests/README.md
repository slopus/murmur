# Encoding tests

Boundary and canonical-form tests for every variable-length integer width.

```text
63 -> 1 byte | 64 -> 2 bytes | 16383 -> 2 bytes | 16384 -> 4 bytes
     canonical round trip             |
overlong/reserved/truncated form -----+-> reject
```

The boundary table prevents multiple byte encodings from representing the same
authenticated MLS value.
