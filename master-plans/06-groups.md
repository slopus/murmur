# MLS sessions

## Destination

A two-person interaction and a many-person interaction use the same MLS session
and group primitive. The MLS engine does not attach chat, document, or other
application meaning to a session. Its descriptor and application events remain
opaque at that layer. Higher Murmur layers may durably route a session to the
built-in contact protocol or to a registered typed synchronization service.

The public API creates a session from an opaque descriptor, sends opaque events,
and adds or removes device members. All ongoing membership control and
application data travel inside MLS. One stable account may authorize several
devices, but every device is a distinct MLS member with its own roster-certified
credential, ratchets, durable store, and authenticated inbox. Murmur
automatically translates an account roster addition or removal into ordinary
MLS membership changes in every known session containing that account. A newly
added device receives a separate MLS Welcome and fresh state through its
authenticated inbox.

## Ordering and delivery

Each outbound MLS delivery has one verifiably bound recipient set containing
every current epoch device member, including the publisher. The legacy relay
publishes one ciphertext atomically to every recipient queue with one UUIDv7
event ID. A negotiated relay durably accepts one fanout manifest and completes
idempotent per-device insertion in event order, retrying failures without a
cross-endpoint transaction. Event IDs are monotonic within each inbox, and the
session never assumes simultaneous fanout completion. Because one multicast
carries one event ID everywhere, the relative event-ID order of two multicasts
is identical in every inbox that holds both; that is the only cross-inbox
ordering property the session relies on, and it is what lets relay order
arbitrate concurrent Commits.

Any current member may publish a Commit. Concurrent Commits against one epoch
are resolved by relay arbitration: each atomic multicast carries one UUIDv7
event ID shared by every recipient inbox, every inbox delivers in event-ID
order, and therefore the first valid Commit for an epoch wins identically at
every member. Publish success only stages a Commit; every member, including its
sender, adopts a Commit from its own relay echo. A Welcome is published only
after its Commit has been adopted from that echo, so a joiner is only ever
bootstrapped into the one adopted epoch: there is no stale, winning, or losing
Welcome, no replacement bootstrap, and a Commit that does not get adopted never
produces a Welcome at all. A member whose staged Commit loses discards the
staged epoch, re-encrypts any dependent staged-epoch application sends against
the winning epoch, and retries the underlying durable membership intent; the
retried Commit publishes its Welcome only once it is adopted in turn. Members
retain a bounded
prior-epoch window so application messages racing a Commit remain decryptable.
Commit authorization is role-based and validated by every member; roles and the
asynchronous membership-intent flow are dictated by
[`10-group-roles.md`](10-group-roles.md). This change ships without backward
compatibility: every session is role-managed, the single-committer flow and its
serialized-proposal machinery are removed rather than retained, and old session
records and Commit wire frames are not decoded or migrated.

The public API never uses relay connectivity, peer presence, session creation,
pending local activation, or a staged membership Commit as permission to send.
Every send encrypts and persists immediately against durable local state. If a
Commit is staged, the send uses and advances the staged post-Commit epoch
without adopting it, and its outbox records the Commit dependency. Murmur
publishes older current-epoch work first, then the Commit; after adopting that
Commit from its own relay echo it publishes every required Welcome, then the
staged-epoch application work. A restart preserves both ratchets and this
dependency order. The other members may remain offline through the entire
operation; only the relay echo of the sender's own Commit gates the Welcome,
never peer presence.

Murmur owns synchronization, outbox retry, replay protection, Commit
resolution, current epochs and ratchets, Welcome processing, and session
lifecycle. Public APIs do not expose that choreography.

Every contact- or service-owned session has a durable routing association.
The built-in contact protocol owns its technical sessions internally. For any
other new session, each registered synchronization service has exactly two
protocol entry points: `onNewSession`, which receives the descriptor and returns
whether the service claims the session, and `onUpdate`, which receives later
updates after a successful claim. Murmur persists the session-to-service owner
mapping. Services are independent, and Murmur models no dependencies between
services or sessions. Service-owned group sessions may send packets and add or
remove members. The technical session proving one contact relationship starts
with two devices and then tracks the verified active-device rosters of both
accounts.

If no registered service claims a new session, Murmur ignores its unknown
updates after durably recording replay and queue progress. Those updates are
acknowledged, cannot block later identity-queue entries, and are not passed to a
raw application `onUpdates` fallback.

## Durability

Before acknowledging a successfully processed delivery, the client atomically
persists the resulting MLS state, replay and queue progress, and a bounded
opaque application update where applicable. It does not expose its store
transaction to the consumer. One identity-wide `sync` loop routes an
inbox-ordered batch to contact handling, registered service callbacks, and the
relevant optional sync callbacks. The sync options include typed contact
lifecycle callbacks such as `onContactRequested`, `onContactAdded`, and
`onContactRemoved`, alongside connection and update lifecycle callbacks.
Contact acceptance or rejection remains an explicit contact action rather than
a return value invented for a lifecycle callback. Murmur atomically drains that
whole local batch only after all relevant asynchronous handling resolves. A
thrown handler or crash before commit returns the same stable event IDs again;
durable exactly-once application effects require application-level idempotency.

A valid bootstrap instead becomes a durable pending local bootstrap or session
together with replay and queue progress before acknowledgement; the application
later activates or ignores it locally. While pending, Murmur continues
processing MLS protocol traffic so the session stays current and durably
buffers opaque application events without exposing them. Each item is
acknowledged after that pending state, buffer, replay, and queue progress are
durable, without waiting for the application.

Pending state and buffered data are strictly bounded. Activation makes buffered
events visible to the appropriate owner in the same identity-wide update loop.
Ignore or overflow terminally rejects the pending session, destroys its secrets
and buffered data, and retains enough replay and rejection state to make retries
harmless. It does not claim to reverse sender-created membership. A built-in
contact bootstrap instead exposes its validated profile hello while pending and
uses the contact accept-or-reject flow.

A malformed, unauthenticatable, undecryptable, unsupported, ignored during
queue processing, or otherwise terminal delivery is durably rejected or
quarantined with replay and queue progress and no application effect before
acknowledgement. The application owns application history; Murmur retains
current protocol state rather than an event-sourced copy of the session.

A client cannot reconstruct a session from the account identity or relay after
trimming. Losing local state requires restoring a backup or authorization and
new Welcomes as fresh device state.

## How we know it is done

- The same opaque descriptor-based MLS API works for two and many members.
- A caller sends opaque events and adds or removes members without
  application-specific behavior in Murmur or the relay.
- Contact- and service-owned sessions retain a durable routing association, and
  each registered service integrates through exactly `onNewSession` and
  `onUpdate` in the one identity-wide synchronization loop.
- Unclaimed session updates are durably ignored and acknowledged without being
  surfaced through raw `onUpdates`, so unknown sessions cannot block the
  identity inbox.
- Ongoing application and control traffic is MLS-protected; there is no friend
  channel or shared relay topic.
- Every current epoch device member, including the publisher, receives each
  ongoing MLS delivery with the same UUIDv7 event ID. Legacy publication is
  atomic; negotiated publication durably retries ordered idempotent target
  insertion. Ordering is guaranteed within an individual inbox, plus the
  consistent relative order of two shared event IDs across inboxes.
- Any member may publish a Commit, membership-changing Commits are validated
  against the session's roles by every member, and shared per-multicast UUIDv7
  event IDs make relay delivery order resolve concurrent Commits for one epoch
  identically everywhere. A losing staged Commit is cancelled and retried from
  its durable membership intent without losing staged application sends, and a
  Welcome publishes only for a Commit its sender has adopted from the relay
  echo, so no joiner is ever bootstrapped from a Commit that was not adopted.
- No session lifecycle or synchronization state blocks an application send.
  Sends during creation, pending local activation, or a staged membership
  change encrypt and persist immediately; staged-epoch work publishes after
  the Commit is adopted from the sender's own relay echo and every required
  Welcome is published, without waiting for peer presence.
- Successful protocol state and any buffered application update are durable
  before queue acknowledgement.
- A valid bootstrap becomes durable pending local state before acknowledgement,
  and the later activate-or-ignore decision does not block the queue.
- A pending session stays current and buffers opaque application events without
  exposure; every queue item remains independently processable and trimmable.
- Pending storage is strictly bounded. Activation exposes buffered events to
  the identity-wide update callback, while ignore or overflow destroys pending
  secrets and data and retains replay and rejection state.
- The public synchronization API owns one inbox loop and optional connection
  and typed contact lifecycle hooks; it routes contact and service packets
  internally, and no application transaction, session-specific drain, or
  public batch commit exists.
- Terminally rejected or quarantined deliveries persist replay and queue
  progress without an application effect before acknowledgement.
- Restarts preserve bounded pending and locally activated sessions, current MLS
  and staged epoch state, dependency-ordered outboxes, replay, and queue
  progress through application-supplied persistence.
- The relay is never treated as session history or recovery storage.
- Account roster additions and revocations automatically converge through
  durable MLS Adds, Welcomes, and Removes across every locally known session
  without sharing sender state or blocking application sends.
