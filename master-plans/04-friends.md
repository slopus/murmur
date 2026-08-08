# Discovery

## Destination

Murmur has public identity discovery, not friends. It defines and validates a
self-contained signed discovery bundle containing a public identity and current
signed MLS KeyPackage material sufficient to attempt a bootstrap. It does not
create a relationship, exchange profiles, or establish a separate channel.

The public identity identifies the recipient's authenticated relay queue.
There are no anonymous request topics or capability addresses. Discovery
material is not retained as a relay directory or list. The application obtains,
shares, or resolves a discovery bundle out of band or through an
application-supplied discovery service. Exact lookup is outside Murmur and the
relay.

## Identity and KeyPackages

An identity exposes one public identity key. Murmur owns its secret material
and the lifecycle of its signed current KeyPackages. The exact key derivation
and bundle encoding remain unspecified.

Anyone who obtains a valid discovery bundle may attempt to bootstrap a session.
That is not proof of an existing relationship, so the recipient must remain in
control of acceptance and implementations must bound unsolicited attempts.

## How we know it is done

- Murmur defines and validates a self-contained signed discovery bundle that
  identifies one public Murmur identity and supplies current KeyPackage
  material suitable for MLS bootstrap.
- The application obtains or shares the bundle out of band or resolves it
  through an application-supplied service.
- Discovery creates no friend record, friend request state machine, profile
  exchange, or pairwise control channel.
- The relay is not used as a retained identity directory, list, or anonymous
  request topic.
- Unsolicited discovery and bootstrap attempts have explicit acceptance and
  spam bounds.
