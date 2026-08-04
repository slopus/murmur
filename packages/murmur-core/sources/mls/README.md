# MLS internals

This directory contains Murmur's browser-safe RFC 9420 subset. It is compiled
as part of `@slopus/murmur` and is not a package export.

```text
Murmur facade
    |
    +-- epoch + Secret Tree
    +-- Commit + UpdatePath
    +-- KeyPackage + Welcome
    `-- cipher-suite and wire codecs
```

The facade owns persistence, relay ordering, outboxes, invitations, replay,
and crash recovery. These modules only implement cryptographic state
transitions and strict bounded codecs.
