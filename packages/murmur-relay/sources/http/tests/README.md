# HTTP tests

The Fetch handler is exercised directly: signed publish, state/events reads,
conflict JSON, blob-link routing, health, CORS, malformed bodies, weighted
rate-limit responses, independent IP/author keys, untrusted forwarding-header
spoofing, and unknown routes. Socket binding is not needed for protocol
confidence. Byte-budget regressions verify that short event and list pages
retain unambiguous continuation information.
