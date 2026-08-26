# Relay

## Destination

The relay is honest but not trusted. We assume the server does its job
honestly and rely on that for a smooth experience, but it can never decrypt
anything. Because it is honest, it may be authoritative for MLS-adjacent
state: it rejects a publication whose recipient set omits a current device of
a targeted account, and it may enforce basic roles as an addition to the local
verification every member still performs — never as a replacement. The server
can stop servicing something; that denial of service is accepted as
unavoidable, since the server could equally shut down.

The relay is a delivery buffer plus the identity directory. It has
one authenticated inbound queue per running client inbox, bounded HTTP reads,
and one authenticated streaming receiver per inbox. It stores three kinds of
data: encrypted deliveries that remain unacknowledged and unexpired, the
identity directory of published prekeys dictated by the identity-directory
plan, and the relay-held session state — membership and roles per session —
that it uses for fanout and basic checks.

Everything the relay stores is linked to the owning account and, where
applicable, the owning session. It also holds each account's current device
roster. Deleting an account removes its directory
entries, device roster, queues, and every other account-linked record. Deleting a session —
an owner-only action dictated by the roles plan — removes that session's
relay state. Cleanup is by ownership, not by anonymity-preserving timeout.

It stores no snapshots, retained chat history, event-sourced application
state, invitation caches, or anonymous topics. It may hold the unencrypted
MLS-adjacent state needed for its additive enforcement, but it cannot
interpret encrypted delivery contents. It does learn
authenticated admission, sender, recipient, exact fanout, timing, and queue
progress; this metadata exposure is accepted. The authentication server
retains only the account, endpoint, and protocol routing needed for
admission, delivery, and ticket issuance.

There is no backward compatibility. Old wire formats and relay schemas are
deleted, not migrated or decoded, and both deployed relays start clean.

## Relay-held session state and fanout

The relay persists MLS session state in some form: for each session it knows
the session identifier, the current member accounts, and the role state —
owner, admins, and policies. It learns this from authenticated, relay-visible
control metadata carried beside the encrypted MLS payloads and applies changes
in its own delivery order, so its view follows the same winning Commit every
member adopts. This state is authoritative for routing and enforcement, never
for decryption: the relay still cannot read any application or MLS secret.

A session send is addressed to the session, not to a recipient list. The relay
derives the exact device fanout itself from its session membership joined with
the current device rosters, so clients do not need to know, fetch, or
enumerate recipient devices for ongoing traffic. Because the relay performs
the protocol honestly, it does basic checks before queueing: the sender must
be a current member device of the session, application sends must satisfy the
session's send policy, and membership and role changes must be authorized by
the role state it holds. These checks are additive; every member still
verifies everything locally, and a member rejects any delivery whose visible
control metadata does not match its encrypted MLS content. Direct
inbox-addressed publication remains for deliveries that precede session
membership — Welcomes, bootstrap material, and relay notifications.

## Publishing

Every publication has a stable delivery ID and one ciphertext, with its exact
recipient set either derived by the relay from session state or, for direct
deliveries, named explicitly. Publication is atomic where one store holds
every inbox: the relay assigns one UUIDv7 event ID and inserts one queue
reference with that ID for every recipient, or inserts nothing. Where fanout
spans endpoints, the accepting endpoint durably records one fanout manifest
with the shared event ID before reporting acceptance, then inserts the
delivery idempotently into every target inbox in event order and retries
incomplete targets until all succeed or the delivery expires.

UUIDv7 event IDs are time ordered and strictly monotonic within each inbox.
There is no numeric or public global sequence, and order across different
inboxes is not a relay guarantee — except that one multicast carries one
event ID everywhere, so the relative order of two multicasts is identical in
every inbox that holds both. That is what lets relay delivery order arbitrate
concurrent Commits. Publication and each target insertion are idempotent
while the delivery record or any queue reference remains.

For every ongoing MLS delivery, the relay-derived fanout contains every
current member device, including the publisher. Concurrent Commits are
resolved by delivery order at the members; the relay's session state follows
that same order, so relay and members converge on the same winner.

The relay holds each account's current device roster as account-linked state
and keeps session fanout consistent with it: every session delivery reaches
every current device of every member account, so a stale sender can never
silently exclude a device that joined after its last look. A sender whose MLS
epoch does not yet cover a newly registered device is told so with the current
roster, adds the new leaf, and re-encrypts before retrying.

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
- A stable delivery ID and its recipient set — relay-derived for session
  sends, explicit for direct deliveries — produce one all-or-nothing
  multicast with one shared UUIDv7 event ID, or durable ordered idempotent
  fanout where a transaction cannot span endpoints.
- A session send names only the session; the relay derives the complete
  current device fanout itself, rejects a sender that is not a current member
  device, rejects an application send that violates the session's send
  policy, and rejects a membership or role change its role state does not
  authorize — all additively to local member verification.
- Members reject a delivery whose relay-visible control metadata does not
  match its encrypted MLS content, so lying to the relay cannot survive
  local verification.
- Queue reads may redeliver until the recipient durably processes and
  acknowledges; acknowledgement is signed, monotonic, idempotent, and trims
  the queue.
- Every delivery carries a strictly sequential per-inbox number; every inbox
  exposes a loss generation that advances exactly when an unacknowledged
  delivery is removed for any reason; fresh relay state issues a new
  unpredictable generation.
- Session fanout always covers every current device of every member account;
  a sender whose epoch does not yet cover a newly registered device is told
  so with the current roster and converges by re-encrypting before retrying.
- Deleting an account removes its directory entries, device roster, queues,
  and other account-linked state; deleting a session removes that session's
  relay state.
- The relay stores nothing but pending deliveries, directory prekeys, device
  rosters, and per-session membership and role state: no history, snapshots,
  invitation cache, topics, anonymous records, or decryption capability.
- No legacy wire format, schema migration, or compatibility shim remains.
