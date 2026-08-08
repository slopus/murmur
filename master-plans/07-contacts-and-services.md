# Contacts and synchronization services

## Destination

Contacts are a built-in, foundational part of Murmur. They are not an optional
plugin and do not restore the pre-v0.3 friend-channel, topic, or retained-event
design. A confirmed contact is represented by a durable two-person technical
MLS session and the mutual typed profile handshake performed through it. This
session is contact and control state, not chat.

Capabilities beyond contacts are optional, strictly typed synchronization
services attached to a Murmur client. A service owns its typed packets and
events, persistence, callbacks, and sessions. Services may depend on contacts or
on other services. Each service is explicitly enabled or disabled, and enabled
dependencies are explicit and validated. Contact and service packets use
versioned, strictly validated typed JSON envelopes encrypted inside MLS. Future
chat is one such service depending on contacts, not behavior built into a
contact.

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

Contact lists, profiles, relationship state, service state, session routing,
and offline outboxes use the application-supplied `MurmurStore` under
Murmur-owned namespaces. They survive restart. Opening the client immediately
restores contacts and service state, so local reads and mutations work offline
before the relay connects or synchronization begins. Durable offline outboxes
converge when connectivity returns.

Murmur persists which built-in protocol or synchronization service owns each
session. One identity-wide synchronization loop routes inbound packets to that
owner automatically. Each service exposes its own typed callbacks; applications
do not inspect raw updates to dispatch service-owned sessions.

A generic group synchronization service provides the common typed path for
application domains: it parses and verifies events, persists its protocol
state, and hands typed events to the application domain. Service-owned sessions
may send packets and add or remove members.

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
- Optional strictly typed services declare and validate dependencies, own their
  persistence and callbacks, and participate automatically in the one
  identity-wide synchronization loop.
- Durable session routing prevents applications from manually dispatching raw
  updates for contact- or service-owned sessions.
- A generic synchronization service supports typed group events and member
  changes, while future chat remains a separate service depending on contacts.
- Local integration and production-relay end-to-end tests cover invitation
  expiry, exact acknowledgement and cleanup, restart recovery, and offline
  convergence.
