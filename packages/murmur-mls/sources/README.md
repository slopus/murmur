# Sources

The public entry point exposes suite primitives, MLS encoding, the epoch key
schedule, ratchet-tree math, and eventually the state machine.

```text
encoding ---> cipherSuite ---> keySchedule
                    \---------> tree / group state
```
