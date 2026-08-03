# Shared-session tests

These tests exercise the published owner/member API over real MLS epochs and a
small in-process opaque relay transport. They cover canonical opaque entries,
batch membership, authenticated posts, encrypted history backfill, restart,
dedupe/collision, and owner-only Commit enforcement.

`harness.ts` holds the in-process relay, callbacks, and loopback ephemeral
fan-out shared by both test files. `sharedSessionEphemeral.test.ts` covers the
non-durable channel and the durable friend control frame: bidirectional frames
under the current epoch, the absence of any durable trace, oldest-first drops
for a stalled peer, per-sender ordering with two friends, a revoke closing
in-flight traffic, replica removal closing the channel, reconnect, frame
bounds, and control delivery, quarantine, and revocation.
