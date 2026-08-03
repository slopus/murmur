# Transport tests

Tests cover byte-identical client/relay signature verification, fixed HTTP
routes and response codecs, injected Fetch, response bounds, and blob
integrity. The canonical public relay URL is pinned as part of the package
contract.

`ephemeralStream.test.ts` drives `HttpRelayTransport` with an injected Fetch
returning a `ReadableStream` the test controls. It covers SSE events split
across chunk boundaries, ignored comments/keepalives/unknown events, a single
oversized event failing the stream instead of buffering forever, an oversized
line delivered whole in one chunk failing before it is decoded or retained, the
retained event name counting against the same per-event cap, a prompt abort
that cancels the reader, and `publishEphemeral` returning the delivered count,
posting raw octet-stream bytes, and surfacing HTTP errors.
