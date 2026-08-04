# Postgres store

Production wraps `pg.Pool`; tests wrap PGlite. A per-topic advisory transaction
lock serializes monotonic sequence allocation and atomic collapse. The package
creates only the clean schema and contains no legacy migration reader. Ordered
reads run in a repeatable-read transaction, use the `(topic_id, seq)` primary
index, and select only `limit + 1` retained candidates.
