# Relay implementation

Wake sources bridge successful store commits to process-local long-poll waiters.
SQLite uses direct in-memory dispatch. Postgres listens on a dedicated
connection; publication itself emits `pg_notify` inside the store transaction.
