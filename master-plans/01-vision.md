# Murmur as a focused stateful MLS library

## Vision

Murmur is a stateful library for discovering a public identity, bootstrapping
an MLS session, and exchanging opaque data through that session. A two-person
interaction and a many-person interaction use the same MLS group primitive.
Friend relationships, pairwise friend channels, chat semantics, and generic
relay topics are not part of Murmur.

It ships as the browser-safe and Node.js-compatible `@slopus/murmur` library.
The relay is internal infrastructure, and application protocols such as chat
and documents live above the library.

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

A relay item is acknowledged only after its queue-processing outcome is
durable. Successful session processing atomically persists Murmur state, replay
and queue progress, and a bounded opaque application update before
acknowledgement. One identity-wide synchronization loop later calls the
application's asynchronous `onUpdates` hook with an inbox-ordered batch spanning
all sessions. After the hook resolves, Murmur atomically drains the whole batch
from local storage. A thrown hook or crash before that internal commit exposes
the same stable event IDs again; applications needing durable exactly-once
effects deduplicate those IDs in their own persistence.

A valid bootstrap becomes a durable pending local bootstrap or session together
with replay and queue progress before acknowledgement; the application later
activates or ignores it locally. While pending, Murmur continues advancing its
MLS state and durably buffers opaque application events without exposing them,
so later queue items can also be acknowledged without waiting. Pending state
and buffered data are strictly bounded. Activation makes its buffered events
visible to the same identity-wide `onUpdates` loop; ignore or overflow
terminally rejects the session and destroys pending secrets and data while
retaining replay and rejection state.

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
   as pending and trims the queue before the application later activates it
   locally or ignores it.
3. **MLS sessions.** Send opaque descriptors, application events, and
   membership changes through the same MLS primitive for two or more members.
4. **Applications.** Define chat, documents, files, and every other meaning
   above Murmur.

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
- The same opaque MLS session API works for two and many members, including
  adding and removing members.
- Queue processing survives redelivery and acknowledges only after durably
  recording queue progress and its successful protocol state plus buffered
  update, pending bootstrap, or terminal rejection.
- One `sync` loop delivers bounded identity-wide batches with stable event IDs
  to an optional asynchronous `onUpdates` hook and commits a whole batch only
  after that hook resolves; an uncommitted batch is returned again after
  restart.
- Realtime delivery streams exact queued events over authenticated SSE in one
  inbox's UUIDv7 order, reconnects from the durable cursor, and may redeliver
  but cannot replace durable acknowledgement.
- No friend state machine, friend channel, generic topic API, CLI, or
  chat-specific protocol remains.
