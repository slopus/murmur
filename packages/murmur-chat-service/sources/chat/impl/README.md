# Chat implementation

Mechanical binary framing, durable records, the retry worker, and attachment
cryptography are private implementation details.

```text
outbox record --worker--> deterministic ciphertext --BlobStore
      |                                      |
      `-------------- chat frame ------------`--> Murmur group

Murmur history --strict decode/dedupe--> transactional projection + cursor
```

Projection/cache keys can be deleted and rebuilt. Outbox and attachment intent
keys are authoritative and must not be deleted.
