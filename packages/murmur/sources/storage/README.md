# Storage

`MurmurStore` is the application-owned durable boundary. It provides atomic
transactions, exact key/value access, and bounded prefix scans. Murmur persists
identity roots, account state, KeyPackage bundles, epochs, pending sessions,
outboxes, replay markers, application updates, and queue continuity here.

Values are defensive byte copies. Prefix scans return lexicographically ordered
keys and enforce a hard maximum result count. Cryptographic code must zero
temporary secret values after use.

`MemoryMurmurStore` is deterministic test support, not production persistence.
