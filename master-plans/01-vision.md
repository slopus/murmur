# Murmur as a stateful library on top of one dumb relay

## Vision

Murmur becomes the dumbest possible stateful library for encrypted group
streams over the internet. Two parties who know each other's public keys can
establish a friend channel and begin adding each other to groups. Everything
else follows from that.

It ships exclusively as the published stateful `@slopus/murmur` library for a
Node.js process or a browser. The application supplies persistence. The library
owns identity keys, friend and bootstrap state, synchronization, MLS epochs,
outboxes and replay, and the durable lifecycle of all of that state.

The current codebase is dead. We are reusing the name and a little of the
concept, and writing the thing again, properly. A two-person interaction and a
many-person interaction use the same opaque descriptor-based MLS group stream
primitive. Murmur has no chat-specific protocol: chat, documents, and every
other application meaning are implemented above it later. The friend channel
remains outside MLS as a bootstrap and control path for private group
invitations.

This is a clean 0.x rewrite from zero. There is no backward compatibility,
migration support, or preservation of legacy APIs, codecs, storage schemas, or
read paths. The old CLI, DirectChat, snapshot and list storage, and multi-relay
surfaces are deleted rather than adapted.

## The relay

There is exactly one relay between the parties. It is still encrypted end to
end — what the relay holds is signed blobs it cannot read — but it is no longer
only a pipe. It keeps state.

The relay is extremely dumb. It stores the ordered events of typed, key-bound
topics and never learns what they mean. Nothing beyond that belongs in it.

It must be cheap to host, both on your own box and on something like Cloudflare
Durable Objects.

### What a topic holds

Every topic has exactly one ordered store of events. There are no snapshots and
no separate lists.

Each event may specify an expiration. An event without an expiration is durable.
Clients recover by reading the retained events in order, then follow new events.

An event may also carry an optional opaque `collapse key` supplied by the
client. When a new event is written, the relay atomically removes every older
event in the same topic with the same collapse key. The relay does not interpret
the key or the event contents.

For example, an edited message is a complete replacement message carrying the
same collapse key. The earlier version does not need to remain.

The API follows from that: read the retained ordered events and subscribe to new
events.

The relay promises storage, not delivery. The stateful library owns catch-up,
outboxes, replay, and the durable lifecycle against this relay.

## Transport

There is one transport, and it goes through exactly one relay. We are dropping
the idea that the transport underneath is neutral and swappable for a local
network, WebRTC, or Bluetooth. There is no multi-relay ordering, failover, or
coordination model.

The application supplies the relay endpoint when it opens the library. Choosing
a different relay means changing that one endpoint. What we do not promise is
that there could be no relay at all: peers must be able to synchronize while
another member is offline, and that needs somewhere to leave state.

## The stateful library

The application opens the library with one relay and a persistence
implementation. The public API stays minimal:

- own one identity and its keys;
- establish friends and the bootstrap channel;
- create a group from an opaque descriptor;
- send opaque group events;
- add and remove group members;
- synchronize internally.

The library owns the synchronization choreography and persists its identity,
friend state, MLS epochs, outboxes, replay state, and group lifecycle through
the application-provided persistence. Scheduling synchronization is an
implementation choice, not public choreography.

Descriptors and group events remain opaque to Murmur. The library protects and
synchronizes the same group primitive from two members upward, while the
application decides what every group and event means.

`@slopus/murmur` is the only Murmur product. The CLI is deleted, and graphical
or chat-specific interfaces belong above the library.

## The layers, in order

1. **Friends.** People find and add each other by public identity key. The
   non-MLS friend channel provides bootstrap and control, including private MLS
   group invitations.

2. **Groups.** Two or more people share the same descriptor-based MLS group
   stream primitive. The library sends opaque events, changes membership, and
   synchronizes all durable state internally.

3. **Applications above Murmur.** Chat, shared documents, files, rooms, and
   every other meaning are separate protocols built later over opaque group
   descriptors and events.

## How we know each step is done

1. Stateful library: it opens with exactly one relay and application-provided
   persistence, survives restarts, and owns its identity, friend, MLS,
   synchronization, outbox, replay, and lifecycle state.
2. Friends: two processes, each with only the other's public identity key,
   exchange profiles through the relay and establish the friend channel.
3. Groups: the same opaque MLS stream works for two or more members, with
   adding and removing a member enforced by crypto rather than the relay.
4. Boundary: no CLI or chat-specific protocol remains, and the relay never
   learns what a topic, descriptor, or event means.
