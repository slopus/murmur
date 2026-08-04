# Storage

SQLite and Postgres/PGlite implementations of one fresh ordered-event schema.
Publishing allocates a monotonic per-topic sequence, records idempotency, and
applies collapse atomically. Reads filter expired rows without requiring
contiguous sequences; the permanent topic head preserves cursor progress.
