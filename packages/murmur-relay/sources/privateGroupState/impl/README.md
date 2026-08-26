# Private-group state implementation

`privateGroupStateStoreSqlite.ts` and `privateGroupStateStorePostgres.ts` own
the clean SQLite and Postgres/PGlite schemas and atomic canonical revision
replacement.

```text
create / replace -> BEGIN IMMEDIATE -> quota + parent checks -> record + entries
challenge        -> bounded expiring row -> one-time consume
```

The current revision and its digest are replaced atomically with the member
entry index. A `(group, encrypted entry)` primary key rejects duplicate logical
members without revealing their account identifiers.
