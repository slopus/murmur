# MLS bootstrap

## Destination

There is no friend channel. Given a verified discovery bundle or KeyPackage
material claimed from the identity directory, Murmur creates an MLS session and publishes the Welcome and initial material to the
recipient's authenticated device inbox. The legacy relay keeps its atomic
publication contract. A negotiated endpoint first durably records publication
and then completes every idempotent target insertion through ordered retry.

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

Pending session state and buffered data are strictly bounded. Exceeding that
bound terminally ignores or rejects the pending session using the same cleanup
as an application ignore.

A malformed, unauthenticatable, undecryptable, unsupported, or otherwise
terminal bootstrap is durably rejected or quarantined with replay and queue
progress and no application effect before acknowledgement. It must not block
later queue entries.

## Safety and abuse

Knowing an identity is enough to attempt bootstrap, not enough to force a
relationship or session into the recipient's application. Murmur must expose
the claimed initiator and opaque session descriptor needed for an informed
accept-or-ignore decision while keeping application semantics above the
library.

Bootstrap processing, pending Welcomes, KeyPackage lifecycle, retry, replay
protection, pending-session buffers, and queue progress belong to Murmur's
persisted state. Relay queue bounds and the separate local pending-state bound
limit unsolicited attempts. Exact MLS and wire encodings remain implementation
details.

## How we know it is done

- A verified discovery bundle or claimed directory KeyPackage material is
  sufficient to create and deliver an MLS bootstrap.
- Initial delivery uses the selected relay protocol's ordinary bounded
  publication: atomic multicast for the legacy relay, or durable ordered fanout
  retry and per-target idempotency for a negotiated endpoint.
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
- After local activation, descriptors, membership control, and application
  data travel through MLS rather than a separate pairwise channel.
- There is no legacy friendship lifecycle or friend-channel state.
