# Relay

## Destination

The relay does one simple job: it stores key-bound topics. A topic has a chain
of events, stored state, and snapshots. The relay retains messages and history
so that clients holding the same keys can come back later and download
everything they need.

Nothing else belongs in the relay. It does not understand what the stored data
means and does not link Murmur identities.

## The first version

The first version has no external account or identity authorization. We assume
people will generally behave honestly instead of designing the protocol around
abuse from the start.

If an open relay is abused, we can stop accepting writes to it while leaving
the existing data readable, move clients to a newer authorized relay, or ban
the abuse. That possibility is not a reason to link identities now.

The relay is deliberately not a maximal-privacy or maximal-anonymity system.
The goal is simpler: we do not want to surveil people or see their data because
it is none of our business.

## Later authorization

An operator may later choose to require additional external authorization, such
as GitHub. Topics on that relay could then be bound to the authorized external
identity or account. We leave this out for now, but expect it may become useful
if a fully anonymous relay is too open.

## How we know it is done

- Clients with the same topic keys can retrieve the stored messages, history,
  and snapshots they need, including after coming back later.
- The relay stores and serves topic state without understanding its contents or
  linking Murmur identities.
- The initial relay works without external account authorization.
- No application behavior beyond this storage role is implemented in the
  relay.
