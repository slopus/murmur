# Transport tests

Verifies exact protected-read challenge signing with an injected browser-safe
Fetch implementation.

```text
fake Fetch challenge -> transport proof bytes -> captured signature
                                          |
expected canonical request ---------------+-> exact match
oversized/malformed response ----------------> rejection
```

No relay service is mocked at the facade level; these tests isolate only the
browser-compatible HTTP adapter.
