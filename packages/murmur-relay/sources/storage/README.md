# Storage

SQLite and Postgres/PGlite implementations of one fresh ordered-event schema.
Publishing allocates a monotonic per-topic sequence, records idempotency, and
applies collapse atomically. Reads filter expired rows without requiring
contiguous sequences; the permanent topic head preserves cursor progress.
Every page reports whether all retained candidates were exhausted after both
count and encoded-byte limits. Reads select at most one lookahead beyond the
count limit instead of scanning and window-counting the whole retained suffix.
The first query returns only sequence and encoded-length metadata. Both stores
then hydrate exactly the selected sequences with an indexed second query inside
the same SQLite or repeatable-read Postgres transaction. They persist the exact
same compact event JSON byte length and share page selection, so budget
boundaries cannot drift between SQLite text and Postgres JSONB representations
or force hydration of every large candidate.

Collapse identity is `(topic, author signing key, collapse key)`. This matters
for public-write `Read Topic` streams, where independent writers must not erase
one another.

Read challenges use indexed expiration, atomic delete-on-consume, and a
transactionally maintained outstanding count. A schema-version marker rejects
legacy layouts before partial clean-schema creation.

```text
topic head ----> monotonically allocated sequence
event ID ------> idempotency receipt
retained rows -> expiration/collapse filtering -> bounded page

read challenge -> store -> atomic consume -> proof accepted once
```

SQLite and Postgres implement this same conformance contract despite different
locking and notification mechanisms.
