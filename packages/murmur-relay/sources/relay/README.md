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

## Ephemeral fan-out

`RelayService` also carries a low-latency, non-durable path. `publishEphemeral`
fans one opaque frame to every local stream subscriber of a topic and stores
nothing; `openStream` registers a subscriber that the HTTP layer drains as SSE.
Delivery is best-effort and in-process only, exposed through the replaceable
`EphemeralFanout` interface with `InProcessEphemeralFanout` as the default.

```text
POST ephemeral ─> fanout.publishFrame(topic) ─> subscriber queues (bounded)
publish/WakeSource ─> #wake(topic) ─┬─> long-poll waiters resolve
                                    └─> fanout.wake(topic) -> subscriber `wake`
```

Each subscriber owns a bounded, drop-oldest queue (`maximumStreamQueueFrames`,
`maximumStreamQueueBytes`); the enqueue side never awaits the reader, so a
stalled consumer causes bounded frame drops rather than memory growth. The total
subscriber count is capped by `maximumConcurrentStreams`. `wake` rides the same
signal as long polls, so a durable publish also nudges open streams and keeps
working across instances through `WakeSource`.
