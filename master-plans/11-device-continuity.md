# Device continuity and reset

## Destination

A device either processes its inbox with zero gaps — every membership change
and every message, in order — or it detects that continuity broke and dies
atomically. Loss is never a degraded mode. There is no state in which a device
silently missed traffic and keeps limping along with stale sessions.

The system has one retention constant: six months. The relay keeps
unacknowledged deliveries for six months, so a device dark for less than six
months drains its inbox completely and loses nothing. A device dark for longer
is definitionally dead and must re-pair.

Continuity is proven, not assumed. The relay stamps every delivery with a
strictly sequential per-inbox number and exposes a per-inbox loss generation
that advances exactly when an unacknowledged delivery is removed for any
reason — expiry, quota eviction, or relay state loss, which issues a new
unpredictable generation. The device durably tracks the last sequence it
processed and the generation it last saw. A matching sequence chain and
unchanged generation is proof of gapless delivery. A gap or a generation
change is certain evidence of loss.

On detected loss the device resets completely. It stops processing, surfaces
one final reset event to the application containing the full snapshot of every
affected session — identifiers, descriptors, membership, and roles — and then
destroys all session state: epochs, ratchets, buffered events, outboxes, and
intents. It keeps its device identity key, device credential, account signing
material where this device holds it, and the account roster. Everything
transport- and session-shaped is destroyed. There is no partial reset and no per-session
survival.

Re-admission reuses the existing roster convergence machinery. The reset
device announces a signed reset generation through its account roster, the
same authenticated channel as device addition and revocation. Every session
member that holds the account observes the announcement and
automatically Removes the dead leaf and re-adds the device with a fresh
Welcome in every session containing that account, exactly as device linking
and revocation converge today. The account never loses membership: membership
is logical and account-level, and a reset costs the device its continuity and
history, never the account its seat. A single-device account re-enters its
sessions through member convergence on its reset announcement.

Dormancy follows the same constant. Sibling devices may revoke a device that
has been silent past six months, since it can never rejoin continuously.
A dormant device that reconnects self-detects its loss generation change and
resets; it does not need to be told.

The application owns backfill. Murmur's contract is: inline delivery is
exactly-once and gapless, or the application receives one reset event before
destruction. After re-admission the same sessions reappear under the same
descriptors, flagged as re-admissions, so the application can match old state
to new sessions and backfill from its own storage, from peers over ordinary
application events, or from a canonical record service. Peers observe the
reset through the existing roster-change callbacks and may offer history.
Murmur itself never stores or replays application history, and deliveries
multicast between the loss and the re-Welcome are gone for that device;
backfill is the application's answer for them.

Relay schema and wire changes migrate in place from the current baseline
without deleting pending data, and the loss-generation bump replaces every
silent unacknowledged removal the relay performs today.

## How we know it is done

- Every relay delivery carries a strictly sequential per-inbox number, every
  inbox exposes a loss generation, unacknowledged removal of any kind advances
  it, acknowledged trimming never does, and fresh relay state issues a new
  unpredictable generation.
- The unacknowledged retention window is six months everywhere the old window
  appeared, and client lifetimes that must outlive it do.
- A device that drains to the tip with an unbroken sequence chain and
  unchanged generation has processed every delivery exactly once and in
  order; the chaos suites cannot construct a silent-loss counterexample.
- A sequence gap or generation change triggers exactly one committed reset:
  the reset is durably recorded first, the application callback delivers the
  complete affected-session snapshot at least once until it resolves, and the
  purge commits exactly once, destroying all session and transport state while
  device identity, account signing material held by this device, device
  credential, and roster are retained.
- A reset adopts the relay's observed head as its new continuity baseline, so
  a reset device cannot loop on the same loss.
- A reset device's signed reset announcement converges automatically: every
  member holding the account Removes the dead leaf and issues a fresh Welcome
  in every shared session, without manual action, while the account remains a
  logical member throughout.
- Re-admitted sessions reappear under their original descriptors flagged as
  re-admissions, and peers observe the reset through existing roster-change
  callbacks.
- A sibling device may revoke a device silent past six months, and a dormant
  device that reconnects resets itself without external instruction.
- Relay schema migration preserves pending deliveries in place.
