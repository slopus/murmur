# Relay implementation tests

`ephemeralFanout.test.ts` covers `InProcessEphemeralFanout` in isolation:
per-topic frame fan-out with delivery counts, dropping the oldest frames past
the frame-count and byte bounds with a single coalesced `drop`, coalesced
`wake`, the concurrent-stream cap plus subscriber-count accounting, and
`waitForActivity` resolving on enqueue, keepalive, and close. The tests use the
subscriber's synchronous `take()` rather than the SSE encoder, so they are
deterministic without sleeping on real streams.
