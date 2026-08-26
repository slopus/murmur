# Synchronization services

## Destination

There is no built-in contact protocol, contact relationship, profile exchange,
or contact acceptance step. Sharing a public identity key is enough: a peer
claims KeyPackage material through the identity directory and instantly
creates sessions and groups with that account, as dictated by the
identity-directory plan.

Capabilities are optional, strictly typed synchronization services registered
on a Murmur client. A service is a class or object with exactly two protocol
entry points: `onNewSession` and `onUpdate`. Services are independent. Murmur
does not model or validate dependencies between services or sessions. Service
packets use versioned, strictly validated typed JSON envelopes encrypted
inside MLS. Chat is a service like any other, not behavior built into Murmur.

## Persistence, routing, and offline use

Session routing and offline outboxes use the application-supplied
`MurmurStore` under Murmur-owned namespaces. They survive restart. Opening the
client immediately restores routing state, so local reads and Murmur mutations
work offline before the relay connects or synchronization begins. Durable
offline outboxes converge when connectivity returns.

Services always mutate and send from local durable state first. Creating a
service group, changing its membership, and sending any number of service
packets require neither relay connectivity nor an online peer. A packet sent
while the group Commit is staged is encrypted immediately for that staged epoch
and durably ordered after the Commit; the service does not wait for group
activation or a remote acknowledgement.

When any new session arrives, Murmur offers its descriptor to registered
services through `onNewSession`. Returning `true` claims the session;
returning `false` declines it. A successful claim durably records the
session-to-service owner mapping, and later updates for that session go to the
owner's `onUpdate`.

If no registered service accepts a new session, Murmur durably consumes and
acknowledges its unknown updates. They are ignored for now, are not surfaced
through a raw application `onUpdates` fallback, and cannot block later entries
in the identity inbox.

Custom services own their persistence independently of `MurmurStore`. Murmur
does not provide service storage or expose its store to services. Service-owned
sessions may send packets and add or remove members. Opening the client
restores the Murmur-owned session owner mapping; each service restores any
application state it needs through its own persistence.

Service handling is an asynchronous part of the ordinary durable batch
boundary. Murmur commits and drains the relevant event batch only after its
handling resolves. If a handler throws or the process crashes first, the same
stable batch is retried.

## Verification

Service routing, offline mutation, restart recovery, and membership changes
are tested with real application stores and a real local relay rather than
mocked services. An explicit end-to-end suite also exercises the deployed
production relay with ephemeral identities. It must acknowledge and clean up
every delivery it creates and allow cached invitation entries to expire.

The v0.3.3 compatibility baseline remains intact: existing public APIs, direct
relay configuration, HTTP/SSE wire formats, and persisted client state stay
backward-compatible. Negotiated tokens, endpoints, and WebSocket delivery are
additive. Relay schemas migrate in place, and the published library remains
browser-safe with its Noble-only runtime dependency boundary.

## How we know it is done

- Knowing a public identity key and holding a contact ticket is sufficient to
  begin sessions and groups with an account; no contact record, profile
  handshake, or acceptance step exists.
- Optional strictly typed services are registered on `MurmurClient`, expose
  exactly `onNewSession` and `onUpdate` to Murmur, own persistence outside
  `MurmurStore`, and participate automatically in the one identity-wide
  synchronization loop.
- Durable session routing prevents applications from manually dispatching raw
  updates for service-owned sessions.
- Returning `true` from `onNewSession` durably assigns that session to the
  service, and later updates reach only its `onUpdate`.
- An unclaimed session is durably ignored and acknowledged without a raw
  `onUpdates` fallback or identity-inbox blockage.
- Callback failure leaves the relevant durable batch available for retry.
- Service-owned sessions support typed group events and member changes; chat
  remains a separate independent service.
- Service groups can be created, changed, and sent to entirely offline.
  Creating, pending, committing, and disconnected states never block service
  sends; their durable outboxes converge in dependency order when the relay is
  reachable.
- Local integration and production-relay end-to-end tests cover invitation
  expiry, exact acknowledgement and cleanup, restart recovery, and offline
  convergence.
