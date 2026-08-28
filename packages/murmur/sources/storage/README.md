# Storage

`MurmurStore` is the application-owned durable boundary. It provides atomic
transactions, exact key/value access, and bounded prefix scans. Murmur persists
identity roots, account state, KeyPackage bundles, epochs, pending sessions,
outboxes, replay markers, application updates, and queue continuity here.

Values are defensive byte copies. Prefix scans return lexicographically ordered
keys and enforce a hard maximum result count. Cryptographic code must zero
temporary secret values after use.

Every store operation receives a `Context` first. `tx(ctx, operation)` is
implemented by the store and invokes `operation` with a transaction context;
the callback continues to call `get`, `set`, `delete`, `list`, and `scan` on
that same store with the supplied context. Nested `tx` calls on the same store
reuse the active transaction. A thrown callback rolls the transaction back,
and `ctx.afterCommit` work runs only after the store commits successfully.

`MemoryMurmurStore` is deterministic test support, not production persistence.
