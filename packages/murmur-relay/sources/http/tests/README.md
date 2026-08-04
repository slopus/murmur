# HTTP tests

Exercises protected-read challenge issuance and consumption plus offline,
future-skew, expiration, and exact-retry publication through the Fetch-compatible
boundary.

```text
request challenge -> sign exact read tuple -> Fetch read -> retained page
reuse challenge ---------------------------> reject
malformed/oversized JSON ------------------> bounded error response
```

These tests prove route adaptation preserves the relay policy's one-use proof
semantics.
