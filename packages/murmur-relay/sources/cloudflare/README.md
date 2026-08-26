# Cloudflare Worker and Durable Objects

The public Worker authenticates a temporary device ticket and routes the
WebSocket to that device's inbox Durable Object. One deployment-wide fanout
object persists a manifest before acceptance, then retries idempotent insertion
into every exact inbox.

Each inbox stores required sequence, acknowledgement, continuity-generation,
pending-item, and pending-byte metadata in one exact shape. Invalid metadata
fails closed. Streams emit continuity before ordered queued deliveries.

The application server remains responsible for user authentication and ticket
issuance. Staging and production require a canonical base64url
`MURMUR_RELAY_TOKEN_SECRET` and exact public `MURMUR_RELAY_ENDPOINT`.
