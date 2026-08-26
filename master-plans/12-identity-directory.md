# Identity directory and instant sessions

## Destination

The relay is an identity directory. An account uploads, for each device in
its roster, a pool of one-use signed MLS prekeys (KeyPackages) plus one
multi-use last-resort prekey. Published material is stored under the
account's public identity key, and that key is the only lookup capability: it
is unguessable, so possessing it is what grants the ability to find the
account. The directory resolves exact identity keys only; there is no
enumeration or listing.

The authentication server releases tickets, and ticket issuance is where rate
limiting happens. A peer that knows an identity key presents a ticket and
fetches the account's device roster and claims prekey material: one one-use
prekey per device, consumed atomically by the claim. When a device's pool is
exhausted, the relay serves its multi-use last-resort prekey instead, so the
account never becomes unreachable.

Murmur keeps its own directory entry healthy automatically: it uploads
prekeys when a device registers, replenishes the pool when the relay
notifies the owning device through its ordinary authenticated inbox that a
prekey was spent, and rotates prekeys from time to time so stale material
ages out. Rotation replaces unclaimed one-use prekeys and the last-resort
prekey; the exact cadence, pool sizes, lifetimes, and ticket encoding remain
unspecified.

There are no DDoS-like protections beyond ticket issuance for now; that
problem will be handled another way.

There is no contact protocol, invitation, or profile machinery. A claimed
prekey set is sufficient to create an MLS session or group including that
account instantly. Incoming sessions follow the generic pending-bootstrap
flow and are routed to registered synchronization services.

## How we know it is done

- Publishing an account uploads a per-device pool of one-use prekeys and one
  multi-use last-resort prekey, resolvable only by the exact public identity
  key.
- A valid ticket fetches the device roster and claims one one-use prekey per
  device; the claim consumes the prekey atomically, and an exhausted pool
  serves the last-resort prekey instead of failing.
- A spent prekey produces a notification through the owning device's
  authenticated inbox, and replenishment is automatic.
- Prekeys rotate automatically: unclaimed one-use prekeys and the
  last-resort prekey are replaced on a cadence without the account becoming
  unreachable.
- Rate limiting lives entirely in ticket issuance; the directory itself adds
  no other abuse protections.
- Sharing an identity key with a friend is sufficient for them to claim
  prekeys and instantly start a session or group; no contact, invitation, or
  profile machinery exists anywhere in Murmur.
