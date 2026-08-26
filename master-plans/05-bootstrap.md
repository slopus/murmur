# MLS bootstrap

## Destination

Given prekey material claimed from the identity directory, Murmur creates an
MLS session and publishes the Welcome and initial material to the recipient's
authenticated inbox. There is no separate discovery bundle, invitation, or
friend channel; the directory claim is the only path to another account's
keys.

The recipient authenticates and decrypts a valid bootstrap and atomically
persists it as a durable pending local bootstrap or session together with
replay and queue progress. It may then acknowledge and trim the relay item
without waiting for an application decision.

While the session is pending, Murmur continues processing later MLS protocol
traffic so its epoch stays current. It durably updates pending protocol,
replay, and queue state and buffers opaque application events without
exposing them, then acknowledges each queue item without waiting for human
input.

The application later activates or ignores the durable pending bootstrap
locally. Activation persists the active session and hands buffered opaque
events through the ordinary durable application boundary. Ignoring destroys
pending session secrets and buffered data while retaining enough replay and
rejection state to make retries harmless. It does not claim to reverse
membership created by the sender. An activated session uses MLS for
everything afterward.

Pending session state and buffered data are strictly bounded. Exceeding that
bound terminally ignores or rejects the pending session using the same
cleanup as an application ignore.

A malformed, unauthenticatable, undecryptable, unsupported, or otherwise
terminal bootstrap is durably rejected or quarantined with replay and queue
progress and no application effect before acknowledgement. It must not block
later queue entries.

## Safety and abuse

Knowing an identity key and holding a ticket is enough to attempt bootstrap,
not enough to force a session into the recipient's application. Murmur must
expose the claimed initiator and opaque session descriptor needed for an
informed accept-or-ignore decision while keeping application semantics above
the library. Ticket issuance rate-limits claims; relay queue bounds and the
local pending-state bound limit unsolicited attempts.

Bootstrap processing, pending Welcomes, prekey lifecycle, retry, replay
protection, pending-session buffers, and queue progress belong to Murmur's
persisted state. Exact MLS and wire encodings remain implementation details.

## How we know it is done

- Claimed directory prekey material is sufficient to create and deliver an
  MLS bootstrap; no other discovery path exists.
- A valid authenticated bootstrap and its replay and queue progress become
  durable pending local state before its relay item is acknowledged.
- Pending sessions continue processing protocol traffic and durably buffer
  opaque application events without exposure or queue blocking.
- Pending state and buffered data are strictly bounded; exceeding the bound
  terminally ignores or rejects the session.
- Terminal invalid or unsupported bootstraps are durably rejected or
  quarantined without an application effect before acknowledgement.
- Durable replay protection prevents retried or replayed bootstrap deliveries
  from activating duplicate local sessions.
- Activation hands buffered events through the ordinary durable application
  boundary; ignore destroys pending secrets and data and retains replay and
  rejection state.
- After local activation, descriptors, membership control, and application
  data travel through MLS rather than any separate pairwise channel.
