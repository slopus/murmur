# Protocol

All current formats are version `1`. Previous Murmur friendship, topic, and
event-log formats are intentionally unsupported.

## Identity and discovery

One 32-byte identity root derives one Ed25519 public identity and the X25519
material used by sealed bootstrap delivery. Internally, keys remain
`Uint8Array`; base64url is used only at serialization boundaries.

`MurmurClient.createInvitation()` creates:

- one signed, self-contained bundle with a five-minute expiry;
- one current public MLS KeyPackage in that bundle;
- the matching one-use private KeyPackage state in the local store.

The client uploads the exact bundle bytes to the relay's non-enumerable
five-minute cache and receives their 32-byte SHA-256 digest. The application
shares only that digest. `resolveInvitation()` fetches the bytes and verifies
the digest, signed expiry, identity signature, and KeyPackage signatures. The
relay is not a directory and cannot resolve or enumerate identities.

The prospective member deletes matching private KeyPackage state when its
Welcome is consumed, or on the next client operation after the five-minute
invitation expires and before any later Welcome can be processed. A creator's
durable one-use claim remains until the KeyPackage's `notAfter` boundary so the
same public KeyPackage cannot be rewrapped and reused.

## Bootstrap

Creating or adding a member prepares one MLS Commit plus one sealed Welcome for
each addition. The Commit outbox contains the complete expected Welcome ID
manifest. Before publishing any Welcome, Murmur validates the Commit, local
staged state, every child record, and every secondary index.

Successful Welcome publications leave durable markers. The Commit publishes
only after all markers are present and all current-epoch application/proposal
outboxes have settled. The sender adopts the Commit only from its own identity
queue echo; a publish response never advances the epoch.

A valid received Welcome creates a bounded `pending` session. MLS protocol
traffic continues while pending. Application events are buffered but not
exposed until `activateSession` makes them eligible for the identity-wide update
loop. `ignoreSession` destroys pending secrets and buffers.

## Realtime queue stream

`POST /v1/queue/events` authenticates with the same domain-separated signed
queue-read object as a bounded read, with `waitMilliseconds: 0`. A successful
response requires `limit: 1` for one-event storage backpressure and is
`text/event-stream`. Each delivery record is:

```text
id: <lowercase UUIDv7>
event: delivery
data: {"eventId":"<same UUIDv7>","delivery":<SignedDeliveryJson>}

```

The relay emits records in that recipient inbox's UUIDv7 order and sends
comment heartbeats without advancing progress. It may buffer, disconnect,
repeat, delay, or omit events; SSE receipt is never acknowledgement. Murmur
processes one record through the ordinary durable queue transaction, sends a
signed acknowledgement, and reconnects from its durable cursor.

Every active-session application event is also indexed locally by that relay
UUIDv7 ID. One `sync({ onUpdates })` loop reads a bounded cross-session batch in
inbox order. Murmur waits for the callback and atomically removes the complete
batch only after it resolves. Missing or failed callbacks leave the batch
pending; no Murmur storage transaction is exposed.

## MLS sessions

Two-member and many-member sessions use the same RFC 9420 profile:

- X25519, HKDF-SHA-256, AES-128-GCM, and Ed25519;
- BasicCredential bound to the Murmur identity key;
- TreeKEM Adds, Removes, Welcome, Commit, and PrivateMessage;
- one explicit epoch committer serialized through MLS authenticated data.

Non-committers send authenticated Add or Remove proposals. The committer lists
them with proposer identity and explicitly accepts a bounded selection.

Application sends clone and persist the post-ratchet epoch plus exact outbox
before publication. Commit preparation persists active and staged epochs
separately. Remove drops prior-epoch receive state immediately; other membership
changes retain a small time- and message-bounded prior-epoch window for in-flight
traffic.

## Delivery and replay

Every sender-signed delivery carries:

- a stable sender-scoped delivery ID;
- sorted unique recipient identities;
- creation and expiration times;
- opaque ciphertext;
- an Ed25519 signature over a domain-separated canonical encoding.

The relay may forget a delivery ID after all references disappear. Recipients
therefore persist sender-plus-delivery-ID replay state. Exact records are
bounded; capacity overflow enters a bounded probabilistic filter whose only
error is rejecting a new delivery. A separate rotating terminal filter
amortizes repeated invalid-input authentication work without accumulating
forever. Replay state and cursor progress commit with the buffered application
update or terminal rejection.

Relay UUIDv7 event IDs provide a monotonic per-inbox cursor and processing-time
floor. Implausible event times reject the page without durable mutation.

## Queue acknowledgement

Reads and acknowledgements are signed by the recipient identity. After durable
processing, the client acknowledges through its latest cursor. Acknowledgement
is monotonic and idempotent while queue state exists. Once an inbox has no
pending references, the relay may reclaim its row; an absent inbox is an empty
state, not retained history.
