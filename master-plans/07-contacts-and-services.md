# Contacts and synchronization services

## Destination

Contacts are a built-in, foundational part of Murmur. They are not an optional
plugin and do not restore the pre-v0.3 friend-channel, topic, or retained-event
design. A confirmed contact is represented by a durable two-person technical
MLS session and the mutual typed profile handshake performed through it. This
session is contact and control state, not chat.

Capabilities beyond contacts are optional, strictly typed synchronization
services registered on a Murmur client. A service is a class or object with
exactly two protocol entry points: `onNewSession` and `onUpdate`. Services are
independent. Murmur does not model or validate dependencies between services or
sessions. Contact and service packets use versioned, strictly validated typed
JSON envelopes encrypted inside MLS. Future chat is a separate service, not
behavior built into a contact.

## Establishing a contact

One identity uploads its signed five-minute discovery bundle to the relay and
shares the returned 32-byte SHA-256 digest out of band. The other identity
resolves and verifies it, accepts the invitation material, creates a two-person
technical MLS session, and sends a typed hello containing its profile.

Murmur receives, decrypts, and validates that hello while the contact session is
pending. It exposes the profile for a contact decision without first activating
the session or handing a raw update to the application. The invited identity
either rejects and destroys the pending contact session, or accepts by sending
its own typed profile hello. Only after both hellos are durably processed does
Murmur persist the confirmed contact and retain the technical session as
cryptographic proof of contact.

A confirmed contact session remains two-person. It may carry strictly typed
contact and control packets, but chat and other application domains use their
own services and sessions.

## Persistence, routing, and offline use

Contact lists, profiles, relationship state, session routing, and offline
outboxes use the application-supplied `MurmurStore` under Murmur-owned
namespaces. They survive restart. Opening the client immediately restores
contacts and routing state, so local reads and Murmur mutations work offline
before the relay connects or synchronization begins. Durable offline outboxes
converge when connectivity returns.

Murmur uses the same session-routing concept for built-in contacts and optional
services, while contacts remain built in rather than becoming a registered
optional service. When any other new session arrives, Murmur offers its
descriptor to registered services through `onNewSession`. Returning `true`
claims the session; returning `false` declines it. A successful claim durably
records the session-to-service owner mapping, and later updates for that session
go to the owner's `onUpdate`.

If no registered service accepts a new session, Murmur durably consumes and
acknowledges its unknown updates. They are ignored for now, are not surfaced
through a raw application `onUpdates` fallback, and cannot block later entries
in the identity inbox.

Custom services own their persistence independently of `MurmurStore`. Murmur
does not provide service storage or expose its store to services. Service-owned
sessions may send packets and add or remove members. Opening the client restores
the Murmur-owned session owner mapping; each service restores any application
state it needs through its own persistence.

The main synchronization options expose optional typed contact lifecycle
callbacks, including `onContactRequested`, `onContactAdded`, and
`onContactRemoved`, with room for further contact lifecycle events. They live
alongside `onConnected`, `onDisconnected`, `onUpdates`, and other main sync
callbacks rather than in a separate polling loop. Contact acceptance and
rejection remain explicit contact actions.

These contact callbacks are asynchronous parts of the ordinary durable batch
boundary. Murmur commits and drains the relevant contact state or event batch
only after its callback resolves. Service handling participates in the same
boundary. If a handler throws or the process crashes first, the same stable
batch is retried.

## Verification

Contacts, service routing, offline mutation, restart recovery, and membership
changes are tested with real application stores and a real local relay rather
than mocked services. An explicit end-to-end suite also exercises the deployed
production relay with ephemeral identities. It must acknowledge and clean up
every delivery it creates and allow cached invitation entries to expire.

The v0.3.3 compatibility baseline remains intact: public APIs and wire formats
stay backward-compatible, persisted client state is read or migrated, and relay
schemas migrate in place. The published library remains browser-safe and keeps
its Noble-only runtime dependency boundary.

## How we know it is done

- Sharing one 32-byte invitation digest is sufficient to begin the built-in
  contact handshake without making discovery itself a relationship.
- A valid incoming typed hello exposes a decrypted and validated profile while
  its contact session is pending.
- Rejection destroys the pending contact session; acceptance sends the local
  typed hello; only mutual hello completion persists a confirmed contact.
- Confirmed contact state and its two-person technical session survive restart
  and are usable offline before synchronization.
- Optional strictly typed services are registered on `MurmurClient`, expose
  exactly `onNewSession` and `onUpdate` to Murmur, own persistence outside
  `MurmurStore`, and participate automatically in the one identity-wide
  synchronization loop.
- Durable session routing prevents applications from manually dispatching raw
  updates for contact- or service-owned sessions.
- Returning `true` from `onNewSession` durably assigns that session to the
  service, and later updates reach only its `onUpdate`.
- An unclaimed session is durably ignored and acknowledged without a raw
  `onUpdates` fallback or identity-inbox blockage.
- The main sync options provide typed contact lifecycle callbacks including
  `onContactRequested`, `onContactAdded`, and `onContactRemoved`; callback
  failure leaves the relevant durable batch available for retry.
- Service-owned sessions support typed group events and member changes, while
  future chat remains a separate independent service.
- Local integration and production-relay end-to-end tests cover invitation
  expiry, exact acknowledgement and cleanup, restart recovery, and offline
  convergence.
