# MLS encoding

Unsigned integers and `opaque<V>` vectors from the MLS presentation language.
Variable-length integers use the RFC 9420 1, 2, or 4-byte encoding. The `11`
prefix is reserved and rejected.

```text
value range       prefix     encoded width
0 .. 63             00          1 byte
64 .. 16383         01          2 bytes
16384 .. 2^30-1     10          4 bytes
reserved            11          reject
```

All higher-level MLS codecs build on this canonical reader/writer boundary.
