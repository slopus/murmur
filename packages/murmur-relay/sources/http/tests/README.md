# HTTP tests

The Fetch handler is exercised directly: signed publish, state/events reads,
conflict JSON, blob-link routing, health, CORS, malformed bodies, weighted
rate-limit responses, independent IP/author keys, untrusted forwarding-header
spoofing, and unknown routes. Socket binding is not needed for protocol
confidence. Byte-budget regressions verify that short event and list pages
retain unambiguous continuation information.

`live.test.ts` is opt-in through `pnpm --filter @murmur/relay test:live`. It
checks the deployed HTTPS welcome, health/CORS behavior, and one read-only
missing-topic response without publishing state.

`stream.test.ts` drives the ephemeral SSE path through the same in-process
handler with a small incremental SSE parser: a frame posted after connect is
delivered, a frame is never persisted (state/list/events stay 404), a stalled
consumer receives bounded drops with a coalesced count, over-sized frames are
rejected with 413, the concurrent-stream cap returns 503, a durable publish
emits `wake`, an aborted request returns the subscriber count to zero, and an
idle stream writes keepalive comments. Timing uses short injected keepalive
intervals rather than long sleeps.
