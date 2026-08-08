# MLS bootstrap

## Destination

There is no friend channel. Given a verified discovery bundle, Murmur creates
an MLS session and atomically publishes the Welcome and initial material to the
recipient's authenticated inbound queue.

The recipient authenticates and decrypts a valid bootstrap and atomically
persists it as a durable pending local bootstrap or session together with replay
and queue progress. It may then acknowledge and trim the relay item without
waiting for an application decision.

While the session is pending, Murmur continues processing later MLS protocol
traffic so its epoch stays current. It durably updates pending protocol, replay,
and queue state and buffers opaque application events or effects without
exposing them, then acknowledges each queue item without waiting for human
input.

The application later activates or ignores the durable pending bootstrap
locally. Activation persists the active session and hands buffered opaque events
or effects through the ordinary durable application boundary. Ignoring destroys
pending session secrets and buffered data while retaining enough replay and
rejection state to make retries harmless. It does not claim to reverse
membership created by the sender. An activated session uses MLS for everything
afterward.

A bootstrap routed to the built-in contact protocol is handled differently.
Murmur internally decrypts and validates its typed profile hello while the
two-person contact session is still pending, then exposes the claimed contact
profile for an accept-or-reject decision. The application does not activate the
session or receive a raw update first. Rejection destroys the pending contact
session. Acceptance sends the local typed profile hello; only the mutual hello
exchange confirms and persists the contact relationship.

Pending session state and buffered data are strictly bounded. Exceeding that
bound terminally ignores or rejects the pending session using the same cleanup
as an application ignore.

A malformed, unauthenticatable, undecryptable, unsupported, or otherwise
terminal bootstrap is durably rejected or quarantined with replay and queue
progress and no application effect before acknowledgement. It must not block
later queue entries.

## Safety and abuse

Knowing an identity is enough to attempt bootstrap, not enough to force a
relationship or session into the recipient's application. For a generic
bootstrap, Murmur must expose the claimed initiator and opaque session
descriptor needed for an informed accept-or-ignore decision while keeping
application semantics above the library. For a contact bootstrap, Murmur owns
the typed profile handshake and exposes the validated profile and contact
decision instead.

Bootstrap processing, pending Welcomes, KeyPackage lifecycle, retry, replay
protection, pending-session buffers, and queue progress belong to Murmur's
persisted state. Relay queue bounds and the separate local pending-state bound
limit unsolicited attempts. Exact MLS and wire encodings remain implementation
details.

## How we know it is done

- A verified discovery bundle is sufficient to create and deliver an MLS
  bootstrap.
- Initial delivery uses the same atomic publication and bounded relay
  idempotency as every other delivery.
- A valid authenticated bootstrap and its replay and queue progress become
  durable pending local state before its relay item is acknowledged.
- Pending sessions continue processing protocol traffic and durably buffer
  opaque application events or effects without exposure or queue blocking.
- Pending state and buffered data are strictly bounded; exceeding the bound
  terminally ignores or rejects the session.
- Terminal invalid or unsupported bootstraps are durably rejected or
  quarantined without an application effect before acknowledgement.
- Durable replay protection prevents retried or replayed bootstrap deliveries
  from activating duplicate local sessions.
- Activation hands buffered events or effects through the ordinary durable
  application boundary. Ignore destroys pending secrets and data, retains
  replay and rejection state, and does not reverse sender-created membership.
- A contact bootstrap exposes its validated typed profile while pending,
  requires no raw application update or generic activation first, and either
  destroys the pending session on rejection or confirms it through a mutual
  typed hello.
- After local activation, descriptors, membership control, and application
  data travel through MLS rather than a separate pairwise channel.
- There is no legacy friendship lifecycle or friend-channel state.
