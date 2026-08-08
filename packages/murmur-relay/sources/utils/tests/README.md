# Utility tests

Canonical JSON, boundary codecs, and UUIDv7 monotonicity are tested
independently because signature compatibility and cursor ordering depend on
their exact bytes. Logger tests pin the visible three-field format, confine ANSI
color to interactive module labels, and verify credential-safe error summaries.

```text
JSON permutations -> canonical bytes -> identical hashes/signatures
invalid boundaries ------------------> reject
same time / clock rollback ----------> strictly increasing UUIDv7
random overflow / max time ----------> carry or explicit exhaustion
log event -> TTY/plain render --------> same fields, controlled ANSI
secret-bearing error -----------------> redacted summary
```

This suite protects deterministic protocol bytes and operational output without
starting the relay service.
