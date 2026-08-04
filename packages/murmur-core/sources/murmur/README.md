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
