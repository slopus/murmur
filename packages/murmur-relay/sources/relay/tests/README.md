# Relay tests

Policy and orchestration coverage for signed identity access, TTL and size
limits, pending idempotency, monotonic trimming, race-free long polling, and
destructive expiration.

```text
initial read -> register waiter -> recheck store -> wake / abort / timeout
```

The race test pauses the second store read and aborts during that window,
guarding against unhandled promise rejection and process termination. It also
pins the per-identity waiter bound.
