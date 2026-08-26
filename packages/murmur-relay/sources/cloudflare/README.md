# Cloudflare Worker and Durable Objects

The public Worker authenticates a temporary device ticket and routes the
WebSocket to that device's inbox Durable Object. One deployment-wide fanout
object persists a manifest before acceptance, then retries idempotent insertion
into every exact inbox.

Owner-linked deliveries also create a deployment-wide session index. An
account-signed deletion installs a durable tombstone, resumes partial inbox
purges idempotently, rejects replay, and advances continuity in every affected
inbox, including historical member inboxes not named by the final MLS notice.

This queue-only adapter does not own the current account roster or directory,
so `delete_account` returns `501 account_deletion_unavailable`. Terminal account
deletion requires the standalone SQLite or PostgreSQL relay, where all linked
state shares one transaction boundary.

Each inbox stores required sequence, acknowledgement, continuity-generation,
pending-item, and pending-byte metadata in one exact shape. Invalid metadata
fails closed. Streams emit continuity before ordered queued deliveries.

The application server remains responsible for user authentication and ticket
issuance. Staging and production require a canonical base64url
`MURMUR_RELAY_TOKEN_SECRET` and exact public `MURMUR_RELAY_ENDPOINT`.
