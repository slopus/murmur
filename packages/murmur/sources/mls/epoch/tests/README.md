# Epoch tests

Coverage for the integrated Remove-plus-Add flow across retained, removed, and
joining members, including staged checkpoint restore, Welcome-to-epoch handoff,
durable restart, application ratchets, and transition cancellation.

```text
epoch E checkpoint -> stage Remove/Add -> serialize staged state
       |                                     |
    restart ----------------------------> adopt/cancel
       `-> application send/open -> generation rollback on failure
```

These tests focus on ownership and recovery around the cryptographic
transitions rather than relay ordering, which the facade suite covers.
