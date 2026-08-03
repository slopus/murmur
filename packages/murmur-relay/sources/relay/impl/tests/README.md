# Relay implementation tests

`ephemeralFanout.test.ts` covers `InProcessEphemeralFanout` in isolation:
per-topic frame fan-out with delivery counts, dropping the oldest frames past
the frame-count and byte bounds with a single coalesced `drop`, coalesced
`wake`, the process-wide and per-topic subscriber caps plus subscriber-count
accounting on both, the aggregate byte budget evicting the longest-backlogged
reader (including bytes already handed to a reader, and rejecting a budget below
one subscriber's queue), and
`waitForActivity` resolving on enqueue, keepalive, and close. The tests use the
subscriber's synchronous `take()` rather than the SSE encoder, so they are
deterministic without sleeping on real streams.
