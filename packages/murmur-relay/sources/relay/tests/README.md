# Relay tests

Policy and orchestration coverage for signed identity access, TTL and size
limits, pending idempotency, monotonic trimming, race-free long polling,
destructive expiration, account ownership, and replay-protected terminal
account deletion. Valid deletion of a missing account has the same no-content
success as deletion of an existing account.

Directory orchestration tests also pin ticket-verifier absence, upload
validation, and exact claim wake behavior; HTTP and store tests cover the full
ticket and consumption lifecycle.

Test stores implement only the current queue seam.

```text
initial read -> register waiter -> recheck store -> wake / abort / timeout
```

The race test pauses the second store read and aborts during that window,
guarding against unhandled promise rejection and process termination. It also
pins the per-identity waiter bound.
