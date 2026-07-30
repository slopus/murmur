# Shared document

An operation-based replicated growable-array text document carried as ordinary
encrypted group application data.

Concurrent inserts at one anchor use canonical operation-ID ordering. Deletes
are out-of-order-safe tombstones. Relays see only opaque MLS payloads and need
no document-specific behavior.

Every apply call requires the actor identity authenticated by the MLS group
layer. Aggregate count and encoded-byte budgets are fixed protocol constants:
replicas retain the same lowest operation IDs regardless of delivery order.
