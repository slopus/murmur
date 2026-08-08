# Storage

Murmur state is built on one ordered byte key/value primitive:

```text
get(key)
set(key, bytes)
delete(key)
scan(prefix, { after?, limit })
transaction(async store => ...)
```

`scan` is lexicographic, prefix-filtered, and page-bounded. Compound durable
keys use `/` separators because v0.3.3 established that persisted namespace.
Contacts, services, routing, MLS checkpoints, inbox state, and outboxes are all
records layered on this same application-supplied `MurmurStore`; none introduces
another database abstraction.

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
state, invitation KeyPackage expiries, and diagnostics without materializing an
entire namespace. Private KeyPackages are deleted when the matching Welcome
consumes them, or on the next client operation after their five-minute
invitation expires and before another Welcome is processed.
