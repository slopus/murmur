# Identity directory and instant sessions

## Destination

The relay is an identity directory. An account uploads, for each authorized
device, a pool of one-use signed MLS KeyPackages plus one multi-use last-resort
KeyPackage. Published material is stored under the account's public identity
key, and that key is the only lookup capability: it is unguessable, so
possessing it is what grants the ability to find the account. The directory
resolves exact identity keys only; there is no enumeration or listing.

The authentication server releases contact tickets, and ticket issuance is
where rate limiting happens. A peer that knows an identity key presents a
ticket and fetches-and-claims KeyPackage material: one one-use package per
authorized device, consumed atomically by the claim. When a device's pool is
exhausted, the relay serves its multi-use last-resort package instead, so the
account never becomes unreachable.

When a package is spent, the relay notifies the owning device through its
ordinary authenticated inbox, and Murmur automatically uploads replacements
without application involvement.

There are no DDoS-like protections beyond ticket issuance for now; that
problem will be handled another way.

There is no built-in contact protocol. No profiles, no typed hello handshake,
and no contact acceptance step are needed. A claimed KeyPackage set is
sufficient to create an MLS session or group including that account instantly.
Incoming sessions follow the generic pending-bootstrap flow and are routed to
registered synchronization services.

Exact pool sizes, package lifetimes, last-resort rotation, and ticket encoding
remain unspecified.

## How we know it is done

- Publishing an account uploads a per-device pool of one-use KeyPackages and
  one multi-use last-resort KeyPackage, resolvable only by the exact public
  identity key.
- A valid contact ticket claims one one-use package per authorized device; the
  claim consumes the package atomically, and an exhausted pool serves the
  last-resort package instead of failing.
- A spent package produces a notification through the owning device's
  authenticated inbox, and replenishment is automatic.
- Rate limiting lives entirely in ticket issuance; the directory itself adds
  no other abuse protections.
- Sharing an identity key with a friend is sufficient for them to claim keys
  and instantly start a session or group; no contact relationship, profile
  exchange, or acceptance handshake exists anywhere in Murmur.
