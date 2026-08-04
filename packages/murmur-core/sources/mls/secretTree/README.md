# Secret tree

RFC 9420 Secret Tree derivation and per-sender handshake/application ratchets.
Generation keys are one-time values. Receivers retain only a bounded number of
skipped keys for out-of-order delivery and reject replay.

Sensitive snapshots retain the current forward-secret node frontier, initialized
sender ratchets, generations, and bounded skipped keys. Restore validates that
cached node secrets form a disjoint frontier and that every initialized sender
has both content ratchets; snapshots never reintroduce the original epoch root.
