# Contact implementation

This directory contains the mechanical contact wire and persistence codecs.

```text
contactCodec.ts
    descriptor <-> exact canonical bytes
    hello/profile/refill/removal packets <-> exact canonical bytes
    admission inventory          <-> bounded signed KeyPackages
    profile    -> bounded immutable JSON

contactRecords.ts
    confirmed contact <-> durable record
    handshake         <-> durable record
    lifecycle event   <-> durable record
    local profile revision <-> durable identity-wide record

contactEngine.ts
    handshake state + profile fanout + offline admission/refill + lifecycle batching
```

Version-2 records are strict canonical JSON. Contact lookups are indexed by
both the 32-byte peer identity and the MLS session ID. In-progress handshakes
and lifecycle callback events have separate prefixes so integration can update
them atomically without changing MLS session persistence.
