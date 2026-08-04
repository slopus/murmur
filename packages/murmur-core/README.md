# @slopus/murmur

The single published Murmur library. It is ESM-only, browser-safe, and has no
runtime dependencies beyond Noble cryptography.

## Public surface

- `Murmur.open({ relay, store, initialProfile?, fetch? })`
- `identityKey`, `profile`, `setProfile()`
- `friends.request/accept/reject/end/list/get`
- `groups.create/send/add/remove/list/get`
- `sync()` as the only explicit convergence boundary
- `close()` / `destroy()` to zero in-memory secrets
- `MurmurStore`, `MemoryMurmurStore`, `RelayFetch`, and compact data types

There are no constructible sub-clients and no package subpath exports.

## Durability

```text
outbound application:
clone epoch -> seal -> atomic(epoch + plaintext intent + exact event) -> publish

outbound Commit:
prepare on clone -> atomic(active E + staged E+1 + exact event)
               -> publish -> ordered echo decides winner -> adopt/replan
```

Every network write is an exact signed event already stored in the durable
outbox. A timeout is ambiguous and the same bytes, identifier, author, and
signature are retried.
