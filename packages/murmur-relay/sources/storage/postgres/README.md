# Postgres store

The Postgres backend depends on a small query/transaction adapter rather than
`pg` concrete types. Production wraps a `pg.Pool`; conformance tests wrap an
in-process PGlite database.

```text
publish
  -> pg_advisory_xact_lock(hash(topic))
  -> INSERT permanent receipt ON CONFLICT DO NOTHING
  -> conflict plan + state mutation + topic seq
  -> insert retained event body
  -> pg_notify (still inside transaction)
  -> commit
```

Schema versioning runs on one dedicated session under `pg_advisory_lock`.
State reads use repeatable-read transactions. Pruning uses try-locks so only one
instance performs each sweep.
