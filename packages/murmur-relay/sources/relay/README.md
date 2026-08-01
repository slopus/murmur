# Relay policy

`RelayService` is the package's main API. It accepts already-decoded protocol
objects, enforces byte/count/timestamp/signature policy, and calls one small
store contract. Its resolved options also carry HTTP blob-size and rate-limit
policy without putting either subsystem into topic persistence.

Long polling follows a register-then-recheck sequence:

```text
read empty -> register waiter -> read again -> park -> wake/timeout -> read
```

The second read closes the park/arrive race. Timeouts remain mandatory even with
Postgres notifications, so a lost LISTEN connection affects latency only.
