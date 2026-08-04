# Utility tests

Canonical JSON and boundary codecs are tested independently because signature
compatibility and ambiguous-input rejection depend on their exact bytes. Logger
tests pin the visible three-field format, confine ANSI color to interactive
module labels, and verify credential-safe error summaries.

```text
JSON permutations -> canonical bytes -> identical hashes/signatures
invalid boundaries ------------------> reject
log event -> TTY/plain render --------> same fields, controlled ANSI
secret-bearing error -----------------> redacted summary
```

This suite protects deterministic protocol bytes and operational output without
starting the relay service.
