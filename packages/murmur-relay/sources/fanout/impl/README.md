# Fanout implementation

The coordinator deliberately blocks later manifests behind the oldest pending
manifest. This is stricter than per-recipient ordering and prevents overtaking
without cross-endpoint transactions.
