# Contacts

This module defines Murmur's built-in mutual contact handshake. Contact state is
anchored by a two-person technical MLS session; it is not a chat session and is
not an optional registered service.

```text
discovery digest
      |
      v
two-person contact session -- hello(profile) --> pending request
      |                                             |
      +<------------- hello(profile) -- accept -----+
      |
      v
durable confirmed contact + offline MLS admission inventory
```

The version-2 hello carries the application profile, fifteen per-contact one-use
MLS KeyPackages, and one reusable last-resort KeyPackage. The one-use pool is
consumed when this contact is added to service sessions. A refill request is
queued before depletion; the last-resort package remains usable repeatedly
while the peer is offline, and a response rotates the complete inventory.

The technical session carries canonical `hello`, `profile_update`,
`admission_request`, `admission_response`, and `remove` packets encrypted inside
MLS. Profile updates carry monotonic revisions; recipients ignore duplicates
and older revisions, durably replace the peer profile, and emit
`onContactUpdated`. Application profiles remain bounded JSON. Codec functions
return defensive immutable values.

`updateContactProfile(profile)` atomically changes the identity-wide local
profile, mirrors it into every active contact, and queues one technical-session
outbox per target. Removing and removed contacts are excluded, while queued
updates survive crashes and disconnection.

Durable record codecs live in `impl/`. They use a separate
`murmur/contacts/v2/` namespace.
