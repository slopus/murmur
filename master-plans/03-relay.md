# Relay

## Destination

The relay is a disposable delivery buffer plus the identity directory. It has
one authenticated inbound queue per running client inbox, bounded HTTP reads,
and one authenticated streaming receiver per inbox. It stores exactly two
kinds of data: encrypted deliveries that remain unacknowledged and unexpired,
and the identity directory of published prekeys dictated by the
identity-directory plan.

Everything the relay stores is linked to the owning account and, where
applicable, the owning session. It also holds each account's current device
roster. Deleting an account removes its directory
entries, device roster, queues, and every other account-linked record. Deleting a session —
an owner-only action dictated by the roles plan — removes that session's
relay state. Cleanup is by ownership, not by anonymity-preserving timeout.

It stores no snapshots, retained chat history, event-sourced application
state, invitation caches, anonymous topics, capability topics, or MLS state.
It does not interpret encrypted delivery contents. It does learn
authenticated admission, sender, recipient, exact fanout, timing, and queue
progress; this metadata exposure is accepted. The authentication server
retains only the account, endpoint, and protocol routing needed for
admission, delivery, and ticket issuance.

There is no backward compatibility. Old wire formats and relay schemas are
deleted, not migrated or decoded, and both deployed relays start clean.

## Publishing

Every publication has a stable delivery ID, one ciphertext, and an exact
recipient set. Publication is atomic where one store holds every inbox: the
relay assigns one UUIDv7 event ID and inserts one queue reference with that
ID for every recipient, or inserts nothing. Where fanout spans endpoints, the
accepting endpoint durably records one fanout manifest with the shared event
ID before reporting acceptance, then inserts the delivery idempotently into
every target inbox in event order and retries incomplete targets until all
succeed or the delivery expires.

UUIDv7 event IDs are time ordered and strictly monotonic within each inbox.
There is no numeric or public global sequence, and order across different
inboxes is not a relay guarantee — except that one multicast carries one
event ID everywhere, so the relative order of two multicasts is identical in
every inbox that holds both. That is what lets relay delivery order arbitrate
concurrent Commits. Publication and each target insertion are idempotent
while the delivery record or any queue reference remains.

For every ongoing MLS delivery, the exact recipient set contains every
current epoch member, including the publisher, and is bound in a way
recipients can verify. The relay applies no Commit semantics.

The relay holds each account's current device roster as account-linked state
and enforces delivery consistency against it: a publication whose recipient
set omits a current device of a targeted account is rejected with the current
roster, so the sender refetches, adds the new device's leaf, and re-encrypts
before retrying. Messages are always delivered to all devices; a stale sender
can never silently exclude a device that joined after its last look.

Publication never waits for a recipient to be online. Murmur may create an
entire dependency-ordered outbox while offline; when the relay becomes
reachable, it publishes each prerequisite before the deliveries that depend
on it. A Welcome publishes only after its Commit has been adopted from the
sender's own relay echo.

## Continuity

Each inbox carries two continuity values alongside its event IDs: a strictly
sequential per-inbox delivery number stamped on every queued delivery, and a
per-inbox loss generation. Whenever the relay removes a delivery reference
that was never acknowledged — expiry, quota eviction, database recovery, or
any other cause — it advances that inbox's loss generation instead of
pretending nothing happened. Acknowledged trimming never changes the
generation. A relay with fresh or restored state issues a new unpredictable
generation. Reads and streams expose the current generation and each
delivery's sequence number.

A device that observes a sequence gap or a generation change knows with
certainty that it missed something; a device that drains to the current tip
without either has proof it processed every delivery in order.

The unacknowledged retention window is six months. A device dark for less
than six months drains its inbox completely and loses nothing; a device dark
for longer is definitionally dead and re-enters through the reset flow
dictated by the continuity plan.

## Receiving and trimming

A recipient reads its queue in relay order through a bounded page or an
authenticated stream carrying each exact queued encrypted delivery with its
UUIDv7 event ID — not a wake hint. The stream cursor advances only through
emitted events; reconnecting starts from the device's durable cursor, so an
unacknowledged event may be redelivered but is not skipped.

Downloading or streaming is not delivery. A successfully processed item
atomically persists current MLS state, replay and queue progress, and any
bounded opaque application update before acknowledgement. A malformed,
unauthenticatable, undecryptable, unsupported, or otherwise terminal item is
durably rejected or quarantined with replay and queue progress and no
application effect before acknowledgement.

Acknowledgement is signed by the recipient and advances monotonically and
idempotently through an inbox UUIDv7 cursor. A crash before acknowledgement
causes expected redelivery. Once every reference to a delivery is
acknowledged or expired, the relay removes the ciphertext record.

## Bounds

Queues have a quota and the six-month maximum delivery TTL. Directory prekey
pools have per-account item quotas. A full queue creates explicit
backpressure. Every unacknowledged removal advances the inbox's loss
generation so the loss is explicit rather than silent. These bounds prevent
abandoned state from consuming storage forever; primary cleanup remains
ownership-based deletion.

## How we know it is done

- One authenticated ordered inbound queue per inbox with bounded reads and
  one authenticated streaming receiver.
- A stable delivery ID and exact recipient set produce one all-or-nothing
  multicast with one shared UUIDv7 event ID, or durable ordered idempotent
  fanout where a transaction cannot span endpoints.
- Queue reads may redeliver until the recipient durably processes and
  acknowledges; acknowledgement is signed, monotonic, idempotent, and trims
  the queue.
- Every delivery carries a strictly sequential per-inbox number; every inbox
  exposes a loss generation that advances exactly when an unacknowledged
  delivery is removed for any reason; fresh relay state issues a new
  unpredictable generation.
- A publication whose recipient set omits a current device of a targeted
  account is rejected with the current roster, and the sender converges by
  re-encrypting for the missing device before retrying.
- Deleting an account removes its directory entries, device roster, queues,
  and other account-linked state; deleting a session removes that session's
  relay state.
- The relay stores nothing but pending deliveries, directory prekeys, and
  device rosters: no history, snapshots, invitation cache, topics, anonymous
  records, or MLS state.
- No legacy wire format, schema migration, or compatibility shim remains.
