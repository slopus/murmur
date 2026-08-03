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
