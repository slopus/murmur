# Secret tree

RFC 9420 Secret Tree derivation and per-sender handshake/application ratchets.
Generation keys are one-time values. Receivers retain only a bounded number of
skipped keys for out-of-order delivery and reject replay.

Sensitive snapshots retain the current forward-secret node frontier, initialized
sender ratchets, generations, and bounded skipped keys. Restore validates that
cached node secrets form a disjoint frontier and that every initialized sender
has both content ratchets; snapshots never reintroduce the original epoch root.

```text
epoch encryption_secret
          |
     Secret Tree frontier
       /              \
sender handshake   sender application
ratchet g=0..n     ratchet g=0..n
       |              |
 one-use keys + bounded skipped-generation cache
```

Derivation erases ancestor secrets as the frontier advances, providing
forward-secret per-sender generations with bounded out-of-order recovery.
