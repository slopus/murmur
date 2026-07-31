# Murmur as a library on top of dumb relays

## Vision

Murmur becomes the dumbest possible way for anyone to talk to anyone else,
encrypted, over the internet. Two parties who know each other's public keys can
start adding each other to topics. Everything else follows from that.

It ships as a library you can drop into a Node.js process or a browser. It gives
you keys, an identity, contact discovery by public key, private messaging, and
later group chats and other shared objects. It does not give you a graphical
interface and it does not tell you what your messages mean.

The current codebase is dead. We are reusing the name and a little of the
concept, and writing the thing again, properly. Because every interesting object
is group-shaped, the group layer should be MLS rather than a homegrown scheme,
and pairwise chat is just the smallest case of it.

## The relay

There is always a relay between the parties. It is still encrypted end to end —
what the relay holds is signed blobs it cannot read — but it is no longer only a
pipe. It keeps state.

The relay is extremely dumb, and nothing beyond this belongs in it:

- Encrypted topics, many-to-many. A public key publishes into a topic; anyone
  can subscribe to it. The relay never learns what is inside.
- A queue of undelivered messages per recipient.
- Blob storage: upload a file, download a file.

It must be cheap to host, both on your own box and on something like Cloudflare
Durable Objects.

### What a topic holds

Every topic has three things: a snapshot, a list of elements, and a log of
events. The snapshot and the list are the permanent state. The list is
essentially the list of messages.

Clients write state by generating an event. The same event can also replace the
snapshot, or change one element of the list — delete, add, replace. Most often
it appends.

The snapshot and the list are each optional, and a topic uses what it needs. A
chat needs the list, because the list is its messages. A document probably does
not: it needs only the snapshot plus events.

The event log is always bounded — a few days, maybe less. The snapshot and the
list are not: the relay stores them permanently, along with the blobs
themselves, so a client can ask for the state instead of replaying history it
can no longer see.

The API follows from that: load the snapshot, load the list, and subscribe to
events.

Retention, simplified: assume for now that a relay never deletes state. A topic
has to see activity at least once every 30 days or it is dropped; clients can
always recreate it and start syncing again, and that is not a hard case.

Relays promise nothing about delivery. Relays could talk to each other — a
client subscribed through several of them would let them agree on what was
delivered and drop their caches — but that is not for the first version.

## Transport

There is one transport, and it goes through a relay. We are dropping the idea
that the transport underneath is neutral and swappable for a local network,
WebRTC, or Bluetooth. Routing is by public key, and a relay sits between
everyone.

Which relay is still the user's choice: it is a rendezvous point, and peers who
want their own instead just change the endpoint. What we no longer promise is
that there could be no relay at all. Two peers must be able to sync when the
other side is offline, and that needs somewhere to leave state — which is
exactly what WebRTC alone cannot do.

## What the library gives its user

- Generate keys, hold an identity.
- Connect to one or more relays.
- A stream of updates per topic, delivered reliably, acknowledged by hand.
- Realtime when online, and still correct when offline: persistence plus an
  almost-live connection inside the group. Relays route a group's events between
  all of its participants.
- Exactly-once delivery into a topic.
- A bounded history of outgoing messages, so a client can resend — possibly
  through a different relay.

Validating what is inside a topic, on the way in and on the way out, is the
library user's job. Identity, finding people, and sharing entities is the
library's job.

A topic is a descriptor — itself encrypted — and it carries its own type. A
client catches up by loading the snapshot and the list, then following events
from there. It cannot replay the whole log, because the log does not go back far.

Adding somebody to a topic is cryptographically protected. When you create a
chat and add someone, they get a notification about the topic, and from then on
messages into it are durable. The first packet can carry the participant list.

## The CLI

The CLI stays. An agent must be able to use Murmur the ordinary way, from the
command line, exactly as it can today, and a person has to be able to drive the
same commands by hand.

That is as far as we go for people, though. Murmur gets no interface built for
humans to live in — that belongs in Happy.

## The layers, in order

1. **Identity.** People add each other as contacts. This needs somewhere
   more-or-less persistent to keep a small encrypted profile — on the order of
   64 KB to a megabyte — with a name and an avatar. It is found by public key
   through a relay, or handed over directly.

2. **Private messaging.** Roughly what Murmur does today: people write to each
   other and send files. Every file is encrypted, always; the client decrypts on
   the fly, and that is how it knows the relay did not touch it. Files sit for
   about 30 days until delivered. People expect no photo to ever be lost, and
   the answer for now is that the relays we host are simply more accommodating
   and lose nothing.

3. **Groups.** Rooms, channels, group chats. You create a room and invite
   friends and agents into it, and they interact there. The unit that gets shared
   is the room itself. This is where MLS is needed.

4. **Other shared objects.** A shared document that several people edit
   collaboratively, encrypted, shareable once you are contacts. Todo lists.
   Whatever custom protocol somebody wants to write on top, mixing realtime and
   non-realtime.

## How we know each step is done

1. Identity: two processes, each with only the other's public key, exchange
   profiles through a relay and end up as contacts.
2. Private messaging: two contacts exchange messages and an encrypted file with
   one side offline for part of it, and nothing is lost, duplicated, or
   reordered.
3. Groups: a room with three or more members, where adding and removing a member
   is enforced by the crypto and not by the relay.
4. Shared objects: a document edited by two people at once converges, over the
   same topic machinery, with no code in the relay that knows it is a document.

Throughout: the relay stays dumb enough that it never learns what a topic
contains, even though it now stores that topic's state, and the library still
loads in a browser.

## Open questions

- How long the event log actually keeps events, and whether one window fits
  chats and documents both.
- Can we actually promise that a file is never lost, or only that our own relays
  try hard?
- When, if ever, relays should coordinate deliveries with each other.
