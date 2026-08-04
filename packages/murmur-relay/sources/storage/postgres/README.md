# Postgres store

Production wraps `pg.Pool`; tests wrap PGlite. A per-topic advisory transaction
lock serializes monotonic sequence allocation and atomic collapse. The package
creates only the clean schema and contains no legacy migration reader.
