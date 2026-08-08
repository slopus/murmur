# Relay

## Destination

The relay has exactly one authenticated inbound queue per public identity.
Murmur assumes one receiver on one active device for each identity. The relay
stores encrypted deliveries only while at least one recipient reference remains
unacknowledged and unexpired.

It stores no snapshots, retained history, event-sourced application state,
lists, anonymous topics, or capability topics. It does not interpret encrypted
contents. It does learn authenticated sender and recipient identities, exact
fanout, timing, and queue progress; this metadata exposure is accepted.

## Publishing

Every publication has a stable delivery ID, one ciphertext, and an exact
recipient set. Publication is atomic: the relay assigns one UUIDv7 event ID and
inserts one queue reference with that ID for every recipient, or inserts
nothing. UUIDv7 event IDs are time ordered and strictly monotonic within each
inbox. There is no numeric or public global sequence, and order across different
inboxes is not a relay guarantee. Publication is idempotent while the delivery
record or any queue reference remains, so retrying that delivery ID does not
append another delivery.

After every reference is acknowledged or expires, the relay removes the
ciphertext and forgets the delivery ID. A later retry may therefore be enqueued
again. Recipient-side durable replay protection must make that redelivery
harmless.

For every ongoing MLS delivery, the exact recipient set contains every current
epoch member, including the publisher, and is bound in a way recipients can
verify. The relay never resolves concurrent MLS Commits. MLS sessions serialize
Commits through their authenticated epoch committer before publication;
non-committers publish MLS Proposals instead. Exact authentication, signatures,
and wire encoding remain implementation details.

## Receiving and trimming

A recipient reads its queue in relay order. Downloading is not delivery. A
successfully processed item atomically persists current MLS state, replay and
queue progress, and any application-owned effect or history before
acknowledgement. A malformed, unauthenticatable, undecryptable, unsupported,
ignored, or otherwise terminal item is instead durably rejected or quarantined
with replay and queue progress and no application effect before
acknowledgement.

Acknowledgement is signed by the recipient and advances monotonically and
idempotently through an inbox UUIDv7 cursor. A crash before acknowledgement
causes expected redelivery. An acknowledgement removes that recipient's queue
reference; once all references are gone, the relay removes the ciphertext
record.

## Bounds

Queues have a quota and a maximum delivery TTL. A full queue creates explicit
backpressure, and expiration defines the maximum supported offline window.
These bounds prevent an abandoned identity from consuming storage forever.
They do not turn the relay into durable history or a recovery system.

## How we know it is done

- Each public identity has one authenticated ordered inbound queue.
- A stable delivery ID and exact recipient set produce one all-or-nothing
  multicast with one shared UUIDv7 event ID.
- UUIDv7 event IDs are time ordered and monotonic within one inbox. The relay
  exposes no numeric global sequence and promises no order across inboxes.
- A delivery ID is deduplicated while its record or any queue reference
  remains; after the relay forgets it, durable recipient replay protection
  handles a late retry.
- Every ongoing MLS delivery includes the publisher and every other current
  epoch member. The relay does not arbitrate Commits; the MLS epoch committer
  serializes them before publication.
- Queue reads may redeliver until the recipient durably processes and
  acknowledges them.
- Terminally rejected or quarantined deliveries persist replay and queue
  progress without an application effect, so they do not block the queue.
- Acknowledgement is recipient-signed, monotonic, idempotent, and trims the
  queue.
- A delivery record disappears after every recipient reference is acknowledged
  or expires.
- Quota and TTL bound abandoned queues and expose backpressure and the maximum
  offline window.
- The relay has no retained event history, snapshots, lists, generic topics, or
  anonymous addressing.
