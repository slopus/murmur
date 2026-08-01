# Store conformance tests

One behavior suite runs unchanged against SQLite `:memory:` and a real PGlite
Postgres engine. It protects backend parity for ordering, versions, conflict
rollback, idempotency, sequence allocation, reset watermarks, pagination,
retention, failed-publish receipt rollback, absent-snapshot generations, future
cursors, fully pruned logs, and byte-bounded materialization.
