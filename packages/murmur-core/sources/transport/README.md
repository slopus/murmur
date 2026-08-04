# Transport

Browser-safe typed topic, event, and single-relay HTTP contracts. Protected reads
automatically acquire a one-use challenge and sign the exact topic, cursor,
limit, and wait duration. Pages carry an explicit `exhausted` continuation
signal alongside their stable topic head. The transport has no snapshots,
lists, blobs, ephemeral stream, relay arrays, or failover behavior.
