# HTTP tests

The Fetch handler is exercised directly: signed publish, state/events reads,
conflict JSON, blobs, health, CORS, malformed bodies, and unknown routes. Socket
binding is not needed for protocol confidence. Byte-budget regressions verify
that short event and list pages retain unambiguous continuation information.
