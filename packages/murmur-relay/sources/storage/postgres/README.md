# Postgres store

Production wraps `pg.Pool`; tests wrap PGlite. A per-topic advisory transaction
lock serializes monotonic sequence allocation and atomic collapse. The package
creates only the clean schema and contains no legacy migration reader. Ordered
reads run in a repeatable-read transaction, use the `(topic_id, seq)` primary
index, select only `limit + 1` retained metadata candidates, and hydrate only
the selected sequence rows under that same snapshot.

```text
BEGIN
  -> advisory lock(topic ID)
  -> allocate head + idempotency receipt
  -> apply collapse + insert retained event
COMMIT -> optional NOTIFY(topic ID)
```

PGlite exercises the same SQL transaction shape in process, while production
adds pooling and cross-process wake notifications.
