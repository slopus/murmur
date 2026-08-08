# Relay implementation

In-process and Postgres queue wake sources reduce long-poll latency. Wakes carry
only a public identity queue ID and are hints; every wake is followed by an
authoritative transactional queue read.

`invitationValidate.ts` reads only the signed time fields needed to enforce the
five-minute retention ceiling. Invitation contents remain opaque and
unauthenticated at the relay:

```text
opaque bundle bytes -> time bounds -> SHA-256 address -> bounded cache
```
