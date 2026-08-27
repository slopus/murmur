# Cloudflare Worker and Durable Objects

The public Worker authenticates a temporary device ticket and routes the
WebSocket to that device's inbox Durable Object. One deployment-wide fanout
object persists a manifest before acceptance, then retries idempotent insertion
into every exact inbox.

Owner-linked deliveries also create a deployment-wide session index. An
account-signed deletion installs a durable tombstone, resumes partial inbox
purges idempotently, rejects replay, and advances continuity in every affected
inbox, including historical member inboxes not named by the final MLS notice.

The singleton fanout object also owns authoritative relay control state in its
Durable Object SQLite database: device rosters, directory pools and ticket-use
counters, and per-session membership, roles, policy, and epoch. A
session-addressed publication advances that state synchronously and stores its
exact roster-derived device set in the retry manifest. Roster mutations and
one-time-prekey claims use the same manifest-first fanout path for their inbox
notifications.

Roster and device-access changes also fan out an ephemeral owner-only
invalidation to active stream sockets in each current device inbox. Request
sockets never receive unsolicited frames, offline devices retain no live hint,
and the invalidation carries no encrypted metadata or authoritative roster
contents.

Terminal account deletion first removes the roster, directory, and every
affected session from control SQLite. The response means this state is already
unreachable and an inbox cascade is durably scheduled; alarms retry each exact
device inbox independently until all account inbox state is gone. The cascade
is intentionally asynchronous and may still be running after the deletion
response.

Each inbox stores required sequence, acknowledgement, continuity-generation,
pending-item, and pending-byte metadata in one exact shape. Invalid metadata
fails closed. Streams emit continuity before ordered queued deliveries.

The public Worker also acts as Happy's authentication ingress. `POST /v2/session` verifies a
WorkOS User Management bearer token and a device-signed proof, then returns a short-lived ticket
bound to that device, the exact deployment WebSocket, and the WorkOS user ID as its admission
principal. `POST /v2/directory-ticket` verifies the same bearer token and returns a short-lived,
eight-claim directory ticket. The singleton fanout object durably limits each WorkOS account to
eight new directory tickets per minute, while other authenticated accounts remain independent.
Neither endpoint exposes the relay signing secret.

Staging and production require a canonical base64url `MURMUR_RELAY_TOKEN_SECRET`, the exact public
`MURMUR_RELAY_ENDPOINT`, and the environment's public `WORKOS_CLIENT_ID`. Cloudflare directory
tickets use `LocalDirectoryTicketIssuer` with issuer `murmur-cloudflare-directory` and the
domain-separated `deriveCloudflareDirectoryTicketSecret()` result as its signing seed.
