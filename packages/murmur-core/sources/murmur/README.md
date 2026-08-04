# Stateful Murmur facade

This module is the only public protocol surface.

```text
application
    |
    v
Murmur
  friends ---- encrypted bootstrap/control ---- relay
  groups  ---- MLS opaque event streams ------- relay
    |
    `---- MurmurStore (application supplied)
```

Mutations persist high-level intent and wake the internal convergence worker.
The worker catches up every discovered topic, retries exact signed outboxes,
processes relay order, adopts invitations, and prepares queued operations.
`sync()` is only an optional observation/test boundary. No relay topic, cursor,
KeyPackage, Welcome, or epoch checkpoint crosses the facade.

Membership checkpoints carry a separate local persistence generation. If
current-epoch applications arrive before an echoed local Commit, adoption
raises the staged next checkpoint to the live generation plus one without
changing its authenticated MLS epoch, transcript, tree, or secrets.

Removed groups are not polled. A later authenticated Add may reactivate the
same group only through a fresh one-use KeyPackage and Welcome bound to the
retained winning Commit; retained opaque application history is preserved.

Per-friend local and remote KeyPackage pools are capped at eight. Exact
retirement frees reservations. If an active peer abandons every bounded local
reservation, convergence surfaces `MurmurKeyPackagePoolExhaustedError` instead
of allocating unbounded private state or silently stalling.

Invalid relay traffic is represented by a 32-entry per-topic metadata ring;
attacker payload bytes are never copied into quarantine. Authenticated MLS
replay markers use a 128-entry ring because the Secret Tree itself rejects an
older ciphertext after its marker ages out. Control replay state remains
durable where pruning could replay semantic effects.
