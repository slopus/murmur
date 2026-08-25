# Relay

## Destination

The legacy relay keeps exactly one authenticated inbound queue per public
identity, bounded HTTP reads, and one recipient-authenticated SSE receiver. Its
public API and wire format remain supported.

The negotiated relay has one authenticated inbox per independently keyed
account device. A main server authenticates an application user and verifies
the device's membership in the signed account roster before issuing a
short-lived token that names the selected endpoint and protocol. The endpoint
may be that server or a stateful edge object behind public ingress. One account
may authorize multiple devices, but each device has its own key, MLS state,
durable store, queue progress, and receiver.

The relay stores encrypted deliveries only while at least one target reference
remains unacknowledged and unexpired. It also provides a strictly bounded,
content-addressed cache for signed discovery bundles. A cached bundle is
available only by the SHA-256 digest of its exact bytes and expires within five
minutes.

It stores no snapshots, retained chat history, event-sourced application state,
anonymous topics, capability topics, or MLS state. The invitation cache is not
enumerable and is not an identity directory. The negotiated authentication
server retains only the account, device, endpoint, and protocol routing needed
for admission and delivery. The relay does not interpret encrypted delivery
contents or trust cached discovery contents. It does learn authenticated user
admission, device, sender, recipient, exact fanout, timing, and queue progress;
this metadata exposure is accepted.

Valid device revocation stops new token issuance, publication, and inbox access
for that device and removes its pending account-owned routing and queue state.
A valid account tombstone does the same for every account device. This
transport revocation does not replace the MLS Remove Commits required by each
session.

Version 0.3.3 and relay schema version 3 are the compatibility baseline. Every
later relay schema upgrade migrates in place without deleting pending data or
requiring a clean database. Pre-v0.3 topic, friendship, and retained-event
schemas remain unsupported.

## Ephemeral invitations

An uploader may place the exact bytes of one signed discovery bundle in the
relay cache. The relay returns the SHA-256 digest of those bytes. A recipient
that receives the digest out of band may fetch the bytes, verify that the digest
matches, and then independently verify the bundle signature, signed expiry, and
KeyPackages.

The relay never lists cached invitations or resolves them by identity. It
enforces a hard five-minute lifetime, per-admission-principal item and byte
quotas, and relay-wide item and byte quotas. Re-uploading the same digest is
idempotent and does not extend its original expiry.

## Publishing

Every publication has a stable delivery ID, one ciphertext, and an exact device
recipient set. Under the legacy protocol, publication stays atomic: the relay
assigns one UUIDv7 event ID and inserts one queue reference with that ID for
every recipient, or inserts nothing.

Negotiated publication does not require a transaction spanning endpoints. The
accepting endpoint durably records one fanout manifest with the shared event ID,
exact target device inboxes, ciphertext, expiry, and per-target progress before
reporting acceptance. It then inserts the delivery idempotently into every
target inbox and durably retries incomplete targets until all succeed or the
delivery expires. Each target drains fanout in event order, so a later event
cannot overtake an earlier retry and become an unfillable inbox gap. Process or
endpoint failure may delay a subset but does not turn a partial attempt into a
completed fanout.

UUIDv7 event IDs are time ordered and strictly monotonic within each inbox.
There is no numeric or public global sequence, and order across different
inboxes is not a relay guarantee. Publication and each target insertion are
idempotent while the delivery record, manifest, or any queue reference remains,
so retries do not append another delivery.

After every negotiated target has been inserted and every resulting reference
is acknowledged or expires, the relay removes the ciphertext and fanout
manifest and forgets the delivery ID. The legacy relay removes its delivery
after every reference is acknowledged or expires as before. A later retry may
therefore be enqueued again. Recipient-side durable replay protection must make
that redelivery harmless.

For every ongoing MLS delivery, the exact recipient set contains every current
device member, including the publishing device, and is bound in a way
recipients can verify. Multiple devices owned by one account are independent
MLS members with roster-certified credentials and independent state. The relay
never resolves concurrent MLS Commits. MLS sessions serialize Commits through their
authenticated epoch committer before publication; non-committers publish MLS
Proposals instead. Exact authentication, token format, signatures, and wire
encoding remain implementation details.

Publication never waits for a recipient to be online. Murmur may create an
entire dependency-ordered outbox while offline, including Welcome deliveries, a
Commit, and application deliveries encrypted for the staged post-Commit epoch.
When the relay becomes reachable, Murmur publishes each recipient's
prerequisites before the deliveries that depend on them. The relay durably
queues those accepted deliveries within its configured bounds; recipient
consumption is not part of sender publication.

## Receiving and trimming

A legacy recipient reads its queue in relay order either through a bounded page
or one recipient-signed SSE connection. A negotiated device connects to the
endpoint and protocol named by its temporary token; the first negotiated
protocol is an authenticated WebSocket. Both transports carry each exact queued
encrypted delivery with its UUIDv7 event ID in that inbox's order rather than a
wake hint. The stream cursor advances only through emitted events. Reconnecting
starts from the device's durable cursor, so an unacknowledged event may be
redelivered but is not skipped.

Downloading or streaming is not delivery. A successfully processed item
atomically persists current MLS state, replay and queue progress, and any
bounded opaque application update before acknowledgement. The application
receives those updates later through its identity-wide synchronization
callback. A malformed, unauthenticatable, undecryptable, unsupported, ignored,
or otherwise terminal item is instead durably rejected or quarantined with
replay and queue progress and no buffered application update before
acknowledgement.

Acknowledgement is signed by the recipient and advances monotonically and
idempotently through an inbox UUIDv7 cursor. A crash before acknowledgement
causes expected redelivery. An acknowledgement removes that recipient's queue
reference; once all references are gone, the relay removes the ciphertext
record.

## Bounds

Queues have a quota and a maximum delivery TTL. The invitation cache has
separate item and byte quotas and a hard five-minute TTL. A full queue or cache
creates explicit backpressure, and expiration defines the maximum supported
offline or invitation window. Fanout manifests and their retry work are bounded
by the same delivery expiry plus separate item and byte quotas. These bounds
prevent abandoned state from consuming storage forever. They do not turn the
relay into durable history, an identity directory, or a recovery system.

## How we know it is done

- The legacy HTTP/SSE protocol remains supported with one authenticated ordered
  inbound queue per public identity and its existing wire contract.
- The negotiated protocol gives each independently keyed account device one
  authenticated ordered inbox and one short-lived token naming its endpoint and
  protocol.
- A legacy stable delivery ID and exact recipient set still produce one
  all-or-nothing multicast with one shared UUIDv7 event ID.
- A negotiated publication becomes durable before acceptance and uses one
  shared event ID plus idempotent, ordered per-target insertion. It retries
  partial fanout without a cross-endpoint transaction until every target is
  complete or the delivery expires.
- UUIDv7 event IDs are time ordered and monotonic within one inbox. The relay
  exposes no numeric global sequence and promises no order across inboxes.
- A delivery ID is deduplicated while its record or any queue reference
  remains; after the relay forgets it, durable recipient replay protection
  handles a late retry.
- Every ongoing MLS delivery includes the publisher and every other current
  epoch member. The relay does not arbitrate Commits; the MLS epoch committer
  serializes them before publication.
- A sender may durably prepare Welcome, Commit, and post-Commit application
  deliveries entirely offline. Later publication preserves their dependency
  order and never waits for any recipient to connect or consume them.
- Queue reads may redeliver until the recipient durably processes and
  acknowledges them.
- Recipient-authenticated SSE and negotiated WebSocket transport stream the
  exact queued deliveries in one device inbox's UUIDv7 order, apply
  backpressure, and reconnect from durable queue progress without changing
  acknowledgement semantics.
- Terminally rejected or quarantined deliveries persist replay and queue
  progress without an application effect, so they do not block the queue.
- Acknowledgement is recipient-signed, monotonic, idempotent, and trims the
  queue.
- A delivery record disappears after every recipient reference is acknowledged
  or expires.
- A signed discovery bundle may be uploaded and fetched only by the SHA-256
  digest of its exact bytes, is never enumerable by identity, expires within
  five minutes, and cannot have its lifetime extended by re-upload.
- Quota and TTL bound abandoned queues and incomplete fanout, expose
  backpressure and the maximum offline window, and separately bound cached
  invitations.
- Every schema upgrade after version 3 migrates in place and preserves pending
  relay data; operators are not required to start from a clean database.
- The relay has no retained event history, snapshots, public identity or
  application lists, generic topics, or anonymous addressing.
- Signed device revocation and account tombstones remove corresponding future
  routing authority and account-owned relay state without pretending to replace
  MLS Remove Commits.
