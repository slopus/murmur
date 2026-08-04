# Stateful facade tests

These tests drive `Murmur` through the real relay HTTP handler backed by an
in-memory SQLite store.

```text
Murmur -- fetch-compatible HTTP --> RelayService --> SQLite :memory:
```

No relay or persistence choreography is mocked. The application-facing store
remains `MemoryMurmurStore`, which supplies real serialized transactions.
