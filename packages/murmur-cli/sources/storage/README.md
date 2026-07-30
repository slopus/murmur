# CLI storage

`SqliteMurmurStore` implements the core durable key-value and transaction
contract on `node:sqlite`. Every public operation joins one serialization gate,
so ordinary writes cannot interleave with transaction rollback.

```text
caller -> serialization gate -> BEGIN IMMEDIATE -> key_values -> COMMIT
```

Values passed to or returned from the adapter are copied at the boundary.
On-disk SQLite, WAL, and shared-memory files are restricted to mode `0600`; the
CLI bootstrap similarly enforces mode `0700` on its data directory.
