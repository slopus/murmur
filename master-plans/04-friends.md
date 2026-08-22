# Discovery

## Destination

Murmur has public device-identity discovery, but discovery alone does not create
a contact. It defines and validates a self-contained signed discovery bundle
containing a public device identity and current signed MLS KeyPackage material
sufficient to attempt a bootstrap. It does not itself create a relationship,
exchange profiles, or establish a separate channel. The built-in contact
protocol may use the verified result to begin its two-device contact handshake.

The public device identity identifies the recipient's authenticated relay
inbox. There are no anonymous request topics or capability addresses. Discovery
material is not retained as a relay directory or list. The application may
share the complete bundle out of band, or upload its exact bytes to the relay's
five-minute content-addressed cache and share the returned SHA-256 digest. The
relay neither enumerates bundles nor resolves identities; the digest is the
only lookup capability.

## Identity and KeyPackages

A device identity exposes one public identity key. Murmur owns its secret
material and the lifecycle of its signed current KeyPackages. An application
user may authorize several device identities, but they have independent roots,
KeyPackages, MLS leaves, and inboxes. The exact account authorization, key
derivation, and bundle encoding remain unspecified.

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
  identifies one public Murmur device identity and supplies current KeyPackage
  material suitable for MLS bootstrap.
- The application may share the bundle itself, or share a 32-byte SHA-256
  digest that resolves only through the relay's non-enumerable five-minute
  cache.
- Discovery itself creates no contact record or profile exchange. Those begin
  only when the built-in contact protocol accepts the verified material and
  bootstraps its technical session.
- The relay is not used as a retained identity directory, list, or anonymous
  request topic; cached bundles are opaque, content-addressed, and expire within
  five minutes.
- Unsolicited discovery and bootstrap attempts have explicit acceptance and
  spam bounds.
