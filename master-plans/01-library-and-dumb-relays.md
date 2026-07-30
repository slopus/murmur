# Murmur as a library on top of dumb relays

## Where we are going

Murmur becomes the dumbest possible way for anyone to talk to anyone else,
encrypted, over the internet. Two parties who know each other's public keys can
start adding each other to topics. Everything else follows from that.

It ships as a library you can drop into a Node.js process or a browser. It gives
you keys, an identity, contact discovery by public key, private messaging, and
later group chats and other shared objects. It does not give you a UI and it does
not tell you what your messages mean.

The current codebase is dead. We are reusing the name and a little of the
concept, and writing the thing again, properly. Because every interesting object
is group-shaped, the group layer should be MLS rather than a homegrown scheme,
and pairwise chat is just the smallest case of it.

## The relay

The relay is extremely dumb, and nothing beyond this belongs in it:

- Encrypted topics, many-to-many. A public key publishes into a topic; anyone
  can subscribe to it. The relay never learns what is inside.
- A queue of undelivered messages per recipient.
- Blob storage: upload a file, download a file.

It must be cheap to host, both on your own box and on something like Cloudflare
Durable Objects.

Retention, simplified: assume for now that a relay never deletes anything. A
topic has to see activity at least once every 30 days or it is dropped; clients
can always recreate it and start syncing again, and that is not a hard case.

Relays promise nothing about delivery. Relays could talk to each other — a
client subscribed through several of them would let them agree on what was
delivered and drop their caches — but that is not for the first version.

## Transports

All routing is by public key. The transport underneath is replaceable: a local
network, WebRTC, Bluetooth, anything. The software is configured with the
transports its peers can reach it on.

The default is a rendezvous point: some relay hosted somewhere. Peers who want
the private internet instead just change the endpoint. Two peers must be able to
sync even when the other side is offline, which is exactly what WebRTC alone
cannot do — it is realtime only, it has no queues, it needs signaling anyway, and
corporate networks hate it.

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

A topic is a descriptor — itself encrypted — and it carries its own type. There
are no relay-side snapshots: since the relay keeps everything, a client replays
the log.

Adding somebody to a topic is cryptographically protected. When you create a
chat and add someone, they get a notification about the topic, and from then on
messages into it are durable. The first packet can carry the participant list.

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

Throughout: the relay stays dumb enough that swapping it for a LAN, WebRTC, or
Bluetooth transport changes nothing above the transport boundary, and the library
still loads in a browser.

## Open questions

- Is WebRTC worth carrying at all, given corporate networks and its lack of
  queues?
- Can we actually promise that a file is never lost, or only that our own relays
  try hard?
- When, if ever, relays should coordinate deliveries with each other.
