# Stateful facade tests

These tests drive `Murmur` through the real relay HTTP handler backed by an
in-memory SQLite store.

```text
Murmur -- fetch-compatible HTTP --> RelayService --> SQLite :memory:
```

No relay or persistence choreography is mocked. The application-facing store
remains `MemoryMurmurStore`, which supplies real serialized transactions.

The lifecycle suite covers restart-safe friend termination, bounded
KeyPackages, staged/competing Commit races, Welcome binding, remove/re-add,
per-topic failure isolation, fresh-relay cursor reset, quarantine/replay bounds,
friend-end cleanup of queued Adds without suppressing group Removes, abortable
close, accepted staged-Add compensation after local or remote friendship end,
guard-sensitive persisted-operation races, and a 500-event offline backlog
restored through one explicit convergence cycle.
