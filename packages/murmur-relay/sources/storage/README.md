# Storage

Persistence boundary for relay hosts. Implementations must make `publish`
idempotent by event identifier and queue one delivery per recipient.

The memory store is correct but ephemeral. Production host adapters use durable
storage and transactions supplied by their runtime.
