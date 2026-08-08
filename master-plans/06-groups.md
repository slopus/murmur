# MLS sessions

## Destination

A two-person interaction and a many-person interaction use the same MLS session
and group primitive. Murmur does not know whether a session represents chat, a
document, or anything else. Its descriptor and application events are opaque.

The public API creates a session from an opaque descriptor, sends opaque events,
and adds or removes members. All ongoing membership control and application
data travel inside MLS. A newly added member receives the MLS Welcome and
initial material through its authenticated identity queue.

## Ordering and delivery

Each outbound MLS delivery has one verifiably bound recipient set containing
every current epoch member, including the publisher. The relay publishes one
ciphertext atomically to every recipient queue with one shared order.

Publishing a Commit, including receiving publish success, only stages it and
never advances or adopts an epoch. Every member, including its publisher,
processes the Commit from its relay echo in shared queue order. The first valid
current-epoch Commit in that order wins, and competing operations replan
against the resulting epoch.

Murmur owns synchronization, outbox retry, replay protection, Commit
resolution, current epochs and ratchets, Welcome processing, and session
lifecycle. Public APIs do not expose that choreography.

## Durability

Before acknowledging a successfully processed delivery, the client atomically
persists the resulting MLS state, replay and queue progress, and the
application-owned effect or history where applicable. A valid bootstrap instead
becomes a durable pending local bootstrap or session together with replay and
queue progress before acknowledgement; the application later activates or
ignores it locally. While pending, Murmur continues processing MLS protocol
traffic so the session stays current and durably buffers opaque application
events or effects without exposing them. Each item is acknowledged after that
pending state, buffer, replay, and queue progress are durable, without waiting
for the application.

Pending state and buffered data are strictly bounded. Activation hands
buffered events or effects through the ordinary durable application boundary.
Ignore or overflow terminally rejects the pending session, destroys its secrets
and buffered data, and retains enough replay and rejection state to make
retries harmless. It does not claim to reverse sender-created membership.

A malformed, unauthenticatable, undecryptable, unsupported, ignored during
queue processing, or otherwise terminal delivery is durably rejected or
quarantined with replay and queue progress and no application effect before
acknowledgement. The application owns application history; Murmur retains
current protocol state rather than an event-sourced copy of the session.

A client cannot reconstruct a session from the relay after trimming. Losing
local state requires restoring a backup or being added again.

## How we know it is done

- The same opaque descriptor-based MLS API works for two and many members.
- A caller sends opaque events and adds or removes members without
  application-specific behavior in Murmur or the relay.
- Ongoing application and control traffic is MLS-protected; there is no friend
  channel or shared relay topic.
- Every current epoch member, including the publisher, receives each ongoing
  MLS delivery in one common relay order.
- Publish success only stages a Commit. The first valid current-epoch Commit in
  relay echo order wins, and competing operations replan.
- Successful protocol state and any application effects are durable before
  queue acknowledgement.
- A valid bootstrap becomes durable pending local state before acknowledgement,
  and the later activate-or-ignore decision does not block the queue.
- A pending session stays current and buffers opaque application events or
  effects without exposure; every queue item remains independently processable
  and trimmable.
- Pending storage is strictly bounded. Activation durably hands off buffered
  events or effects, while ignore or overflow destroys pending secrets and data
  and retains replay and rejection state.
- Terminally rejected or quarantined deliveries persist replay and queue
  progress without an application effect before acknowledgement.
- Restarts preserve bounded pending and locally activated sessions, current MLS
  state, outboxes, replay, and queue progress through application-supplied
  persistence.
- The relay is never treated as session history or recovery storage.
