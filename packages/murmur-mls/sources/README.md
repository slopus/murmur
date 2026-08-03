# Sources

The public entry point exposes suite primitives, MLS encoding, the epoch key
schedule, ratchet-tree math, and eventually the state machine.

The `sharedSession` domain composes the MLS channel, Murmur client/store,
DirectChat invitation delivery, and encrypted blob primitives into an
owner-controlled transport for opaque Rig transcript projections. It is
published from both `@slopus/murmur/mls` and
`@slopus/murmur/sharedSession`.

```text
encoding ---> cipherSuite ---> keySchedule
                    \---------> tree / group state
```
