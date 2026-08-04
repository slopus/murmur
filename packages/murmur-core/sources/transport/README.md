# Transport

Browser-safe typed topic, event, and single-relay HTTP contracts. Protected reads
automatically acquire a one-use challenge and sign the exact topic, cursor,
limit, and wait duration. Pages carry an explicit `exhausted` continuation
signal alongside their stable topic head. The transport has no snapshots,
lists, blobs, ephemeral stream, relay arrays, or failover behavior.

```text
Murmur exact outbox -> signed event -> one HTTP relay
                                      |
topic capability -> protected read -> ordered page + stable head
                                      |
                                 cursor persistence
```

This layer transports opaque bytes and capability proofs; friend and MLS
semantics remain entirely above it.
