# Relay

## Destination

The relay does one simple job: it stores key-bound topics. A topic has a chain
of events, stored state, and snapshots. The relay retains messages and history
so that clients holding the same keys can come back later and download
everything they need.

Nothing else belongs in the relay. It does not understand what the stored data
means and does not link Murmur identities.

## Topic authorization

Read and write authorization are independent capabilities bound to keys. Every
durable write is signed.

There are three topic types:

- A `Write Topic` requires the designated key for writes.
- A `Read Topic` allows writes by any correctly signing author, but reading or
  listening requires proof by signature from the designated key.
- A `Read and Write Topic` requires designated key authorization for both
  writing and reading or listening.

An inbox is an application of a `Read Topic`, not another topic type.

Topics are named, but their identity and address include the exact topic type,
the relevant authorization public key or keys, and the topic name. The same
name under different keys or a different type is a different topic. Different
names under the same type and authorization key or keys are also different
topics. Each has its own events, state, history, and snapshots.

One authorization key may deliberately scope and authorize several separately
named topic streams. This key reuse is the intended namespace model. The relay
can correlate topics in the same capability-key namespace, but it still cannot
link that capability key to a Murmur identity.

These topic keys are relay capabilities, not Murmur identities, and the relay
does not link them to Murmur identities. The exact request challenge, key
derivation, signature exchange, and wire mechanics remain unspecified.

## The first version

The first version has no external account or Murmur identity authorization. We
assume people will generally behave honestly instead of designing the protocol
around abuse from the start.

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

- Clients holding a topic's required read capability can retrieve the stored
  messages, history, and snapshots they need, including after coming back
  later.
- Every durable write is signed, and read and write capabilities are enforced
  independently.
- A `Write Topic`, `Read Topic`, and `Read and Write Topic` enforce their
  designated capabilities independently.
- A topic is identified by its exact type, relevant authorization public key or
  keys, and name. One key may authorize several names, and every name has
  separate topic state.
- An inbox uses a `Read Topic`: it accepts any correctly signed write but
  exposes its contents only to the designated read capability.
- The relay stores and serves topic state without understanding its contents or
  linking Murmur identities.
- The initial relay works without external account authorization.
- No application behavior beyond this storage role is implemented in the
  relay.
