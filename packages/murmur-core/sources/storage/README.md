# Storage

The core depends on a minimal asynchronous byte key-value store. Browser
applications can back it with IndexedDB; Node applications can use SQLite. The
included memory implementation is for tests and ephemeral processes.

All facade-owned keys live under the new `murmur/v1/` namespace. Stores must
return defensive byte copies and must roll a transaction back when its callback
throws. Murmur does not require or attempt nested transactions.
