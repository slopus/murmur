# Storage

The core depends on a minimal asynchronous byte key-value store. Browser
applications can back it with IndexedDB; Node applications can use SQLite. The
included memory implementation is for tests and ephemeral processes.

Keys are namespaced by their owning domain (`client/`, `mls/`, and so on).
