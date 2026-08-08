# Storage

The core depends on a minimal asynchronous byte key-value store. Browser
applications can back it with IndexedDB; Node applications can use SQLite. The
included memory implementation is for tests and ephemeral processes.

All library-owned keys live under the `murmur/` namespace. Stores must
return defensive byte copies and must roll a transaction back when its callback
throws. Murmur does not require or attempt nested transactions.

```text
Murmur engine
    |
    +-- get/set/delete
    +-- scan(prefix, after, limit) -> bounded ordered page
    `-- transaction(callback) ----> atomic commit or full rollback
                                      |
                                  application store
```

The bounded scan is used for session indexes, outboxes, buffered events, replay
state, and diagnostics without materializing an entire namespace.
