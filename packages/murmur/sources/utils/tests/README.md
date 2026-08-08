# Utility tests

Tests here cover utility-level codecs and deterministic serialization.

```text
arbitrary bytes -> base64url -> original bytes
JSON values ----> canonical ordering -> identical signed bytes
invalid text/shape ------------------> strict rejection
```

Failures here would change identifiers or signatures across every higher-level
protocol, so the tests stay independent of facade behavior.
