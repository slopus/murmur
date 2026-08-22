# Cloudflare Worker and Durable Objects

The public Worker authenticates a temporary device ticket and routes the
WebSocket to that device's inbox Durable Object. Publications are persisted by
one deployment-wide sequencing/fanout Durable Object before acceptance, then
retried into per-device inbox Durable Objects with idempotent inserts.

The application main server remains responsible for user authentication and
for calling `createRelaySessionFetchHandler` with its account-to-device
authorization policy. It returns the Worker's `wss:` endpoint in the ticket.
