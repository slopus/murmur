# Murmur as a focused stateful MLS library

## Vision

Murmur is a stateful library for discovering a public identity, bootstrapping
an MLS session, establishing a built-in contact relationship, and exchanging
data through typed synchronization services. A two-person interaction and a
many-person interaction use the same MLS group primitive. Contacts are
foundational Murmur state. Chat remains an optional independent service, and
the old friend-channel and generic relay-topic machinery are not part of
Murmur.

It ships as the browser-safe and Node.js-compatible `@slopus/murmur` library.
The relay is internal infrastructure. Chat, documents, and other application
protocols live in optional typed services rather than in the relay or the MLS
engine.

The pre-v0.3 rewrite remains a clean break: its APIs, codecs, relay topics,
storage schemas, and CLI are unsupported. Version 0.3.3 is the compatibility
baseline. From that release onward, public library APIs and wire formats remain
backward-compatible, persisted client state remains readable or is migrated,
and relay schemas migrate in place without deleting pending data or requiring a
clean database.

## One relay and one receiver

There is exactly one relay. Each public identity has one authenticated inbound
queue, and Murmur assumes one receiver on one active device for that identity.
The relay stores encrypted deliveries that remain unacknowledged and unexpired.
It may also hold a signed discovery bundle for at most five minutes under the
SHA-256 digest of its exact bytes. It stores no snapshots, retained history,
event-sourced application state, lists, or anonymous capability topics.

Identity-linked sender, recipient, timing, queue, and fanout metadata are an
accepted tradeoff. Murmur promises encrypted contents, not anonymous routing.

## Ownership of state

The application supplies transactional persistence for Murmur and owns
application history and effects, but Murmur never exposes its storage
transaction to application code. Murmur owns identity secrets, current MLS
epoch and ratchet checkpoints, KeyPackages, Welcomes, outboxes, replay and queue
progress, pending-session buffers, session lifecycle, and synchronization. For
realtime receiving, the relay streams the exact queued encrypted deliveries
over one recipient-authenticated SSE connection in inbox UUIDv7 order.

Every local session operation works offline and completes against durable local
state before Murmur lazily shares its outboxes with the relay. Relay
connectivity, peer presence, session creation, pending local activation, and a
staged membership Commit never make `send` wait or reject. A send made while a
Commit is staged encrypts immediately with the staged post-Commit epoch,
durably advances that staged ratchet, and is ordered after its prerequisite
Welcome and Commit. The sender still adopts the Commit as its active epoch only
from its authenticated queue echo; adoption is not permission to send.

A relay item is acknowledged only after its queue-processing outcome is
durable. Successful session processing atomically persists Murmur state, replay
and queue progress, and a bounded opaque application update before
acknowledgement. One identity-wide synchronization loop routes an inbox-ordered
batch to built-in contact handling, registered session owners, and the relevant
main sync callbacks. The main sync options include `onUpdates` and typed contact
lifecycle callbacks, but `onUpdates` is never a fallback for an unclaimed
session. Only after all relevant asynchronous handling resolves does Murmur
atomically drain the whole local batch. A thrown handler or crash before that
internal commit exposes the same stable event IDs again; applications needing
durable exactly-once effects deduplicate those IDs in their own persistence.

A valid bootstrap becomes a durable pending local bootstrap or session together
with replay and queue progress before acknowledgement; the application later
activates or ignores it locally. While pending, Murmur continues advancing its
MLS state and durably buffers opaque application events without exposing them,
so later queue items can also be acknowledged without waiting. Pending state
and buffered data are strictly bounded. Activation makes its buffered events
visible to the appropriate owner in the same identity-wide loop; ignore or
overflow terminally rejects the session and destroys pending secrets and data
while retaining replay and rejection state. Built-in contact bootstraps instead
expose their validated profile hello while pending and follow the contact
accept-or-reject flow.

Malformed, unauthenticatable, undecryptable, unsupported, ignored during queue
processing, or otherwise terminal deliveries are durably rejected or
quarantined with replay and queue progress and no application effect before
acknowledgement. A crash before acknowledgement causes expected redelivery.

Relay replay is not a recovery mechanism. Losing the local store or device
loses protocol state and application history; recovery requires a backup or
being added again.

## The layers, in order

1. **Discovery.** Define and validate a self-contained signed bundle containing
   a public identity and current KeyPackage material without creating a friend
   relationship. An application may share it directly, or upload it to the
   relay's five-minute content-addressed cache and share only its SHA-256
   digest. The recipient fetches by that digest and rejects an expired or
   invalid bundle.
2. **Bootstrap.** Create an MLS session and deliver its Welcome and initial
   material to the recipient's authenticated queue. The recipient persists it
   as pending and trims the queue before generic application acceptance or
   built-in contact handling.
3. **MLS sessions.** Send opaque descriptors, application events, and
   membership changes through the same MLS primitive for two or more members.
4. **Contacts.** Use a two-person technical MLS session and a mutual typed
   profile hello to establish durable cryptographic proof of contact.
5. **Synchronization services.** Register optional independent typed services
   on the client. Each service may claim a new session from its descriptor and
   then owns later updates routed through that durable association.
6. **Applications.** Register typed synchronization services for domains such
   as chat, documents, or files.

## How we know it is done

- `@slopus/murmur` opens with one relay and application-supplied transactional
  persistence in a browser or Node.js process without exposing storage
  transactions through its session API.
- Two identities can discover the material needed to bootstrap an MLS session,
  and the recipient can durably receive it without waiting for the application
  to activate or ignore it.
- A relay-cached discovery bundle is non-enumerable, addressed only by the
  SHA-256 digest of its exact bytes, expires within five minutes, and cannot
  extend the bundle's signed lifetime or the owner's matching private
  KeyPackage state.
- A pending session stays cryptographically current under a strict storage
  bound; activation durably hands off buffered events or effects, while ignore
  or overflow terminally rejects and destroys pending secrets and data.
- A two-person contact session becomes durable contact proof only after both
  identities exchange and process their typed profile hellos; rejection
  destroys the pending contact session.
- Optional strictly typed synchronization services persist their state and
  participate in the identity-wide sync loop through exactly `onNewSession`
  and `onUpdate`. A successful new-session claim durably routes later updates
  to that service.
- The same MLS session engine works for two and many members, including adding
  and removing members in service-owned sessions.
- Every session operation works from durable local state while offline. No
  session or synchronization state blocks `send`; sends against a staged
  membership epoch are encrypted and persisted immediately, survive restart,
  and publish only after their prerequisite Welcome and Commit.
- Queue processing survives redelivery and acknowledges only after durably
  recording queue progress and its successful protocol state plus buffered
  update, pending bootstrap, or terminal rejection.
- One `sync` loop delivers bounded identity-wide batches with stable event IDs
  to built-in contact handling, registered service callbacks, and the relevant
  optional sync callbacks. Contact lifecycle callbacks include
  `onContactRequested`, `onContactAdded`, and `onContactRemoved`. Murmur commits
  and drains a whole batch only after its asynchronous handling resolves; an
  uncommitted batch is returned again after restart.
- A session that no registered service claims has its unknown updates durably
  consumed and acknowledged without a raw `onUpdates` fallback, so it cannot
  block the identity inbox.
- Realtime delivery streams exact queued events over authenticated SSE in one
  inbox's UUIDv7 order, reconnects from the durable cursor, and may redeliver
  but cannot replace durable acknowledgement.
- No legacy friend state machine, friend channel, generic topic API, CLI, or
  built-in chat-specific protocol remains.
