# Cloudflare Worker and Durable Objects

The public Worker authenticates a temporary device ticket and routes the
WebSocket to that device's inbox Durable Object. Publications are persisted by
one deployment-wide sequencing/fanout Durable Object before acceptance, then
retried into per-device inbox Durable Objects with idempotent inserts.

Private-group credential challenges and account-signed blind issuance remain
stateless at public Worker ingress. Proof, token, and canonical-record routes
are selected by the canonical opaque-group header and forwarded to one Durable
Object per opaque group. Each object permanently pins its opaque ID and stores
only the current encrypted record, its opaque member index, and bounded
one-use presentation challenges. Private-group Durable Object state has one
clean beta format and no legacy decoder.

Each inbox object durably retains its next sequence, acknowledged sequence, and
loss generation. Existing objects lazy-migrate in place without dropping
pending records; migration issues a fresh unpredictable generation. Streams
send continuity before queued deliveries.

The application main server remains responsible for user authentication and
for calling `createRelaySessionFetchHandler` with its account-to-device
authorization policy. It returns the Worker's `wss:` endpoint in the ticket.

Both staging and production require `MURMUR_PRIVATE_GROUP_SECRET` as a
canonical unpadded base64url encoding of exactly 32 bytes. Values must differ
between environments and from `MURMUR_RELAY_TOKEN_SECRET`.
