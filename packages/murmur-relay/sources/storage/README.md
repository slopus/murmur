# Storage

SQLite and Postgres/PGlite implementations of one fresh ordered-event schema.
Publishing allocates a monotonic per-topic sequence, records idempotency, and
applies collapse atomically. Reads filter expired rows without requiring
contiguous sequences; the permanent topic head preserves cursor progress.
Every page reports whether all retained candidates were exhausted after both
count and encoded-byte limits. Reads select at most one lookahead beyond the
count limit instead of scanning and window-counting the whole retained suffix.
Both stores persist the exact same compact event JSON byte length and share page
materialization, so budget boundaries cannot drift between SQLite text and
Postgres JSONB representations.

Collapse identity is `(topic, author signing key, collapse key)`. This matters
for public-write `Read Topic` streams, where independent writers must not erase
one another.

Read challenges use indexed expiration, atomic delete-on-consume, and a
transactionally maintained outstanding count. A schema-version marker rejects
legacy layouts before partial clean-schema creation.
