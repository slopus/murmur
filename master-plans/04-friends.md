# Discovery

## Destination

Murmur has public account-identity discovery, but discovery alone does not
create a contact. It defines and validates a self-contained signed discovery
bundle containing a public account identity, an authorized device, and current
signed MLS KeyPackage material sufficient to attempt a bootstrap. It does not
itself create a relationship, exchange profiles, or establish a separate
channel. Alongside this bundle flow, the relay is an identity directory:
published per-device KeyPackage pools are resolvable by the exact public
identity key and claimed with a contact ticket, as dictated by the
identity-directory plan.

The authorized device identifies the recipient's authenticated relay inbox,
while the stable account identity is what a peer verifies. There are no
anonymous request topics or capability addresses. The application may
share the complete bundle out of band, or upload its exact bytes to the relay's
five-minute content-addressed cache and share the returned SHA-256 digest. The
relay never enumerates bundles, directory entries, or identities; an exact
digest or an exact public identity key is the only lookup capability, and an
identity key is unguessable.

## Identity and KeyPackages

An account exposes one stable public identity and a signed, versioned device
roster. Murmur owns each device's secret material and the lifecycle of its
signed current KeyPackages. Authorized devices have independent keys,
KeyPackages, MLS leaves, and inboxes. The exact account-key derivation, recovery
custody, and bundle encoding remain unspecified.

The signed discovery lifetime is at most five minutes. Murmur drops the
matching private one-use KeyPackage state when that invitation expires or is
consumed. A recipient independently verifies the downloaded bytes against the
shared digest and rejects an expired bundle even if an untrusted relay returns
it.

Anyone who obtains a valid discovery bundle may attempt to bootstrap a session.
That is not proof of an existing relationship, so the recipient must remain in
control of acceptance and implementations must bound unsolicited attempts.

## How we know it is done

- Murmur defines and validates a self-contained signed discovery bundle that
  identifies one public Murmur account and authorized device and supplies
  current KeyPackage material suitable for MLS bootstrap.
- The application may share the bundle itself, or share a 32-byte SHA-256
  digest that resolves only through the relay's non-enumerable five-minute
  cache.
- Discovery itself creates no relationship record or profile exchange; there
  is no built-in contact protocol.
- The relay resolves only exact identity keys or exact digests and never
  enumerates or lists; cached bundles are opaque, content-addressed, and
  expire within five minutes.
- Unsolicited discovery and bootstrap attempts have explicit acceptance and
  spam bounds.
