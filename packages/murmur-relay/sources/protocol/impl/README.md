# Protocol implementation

Mechanical transformations for strict wire decoding, canonical event encoding,
signature verification, and event fingerprinting. Public callers use the
exports from the parent module.

```text
JSON topic/event -> strict field decode -> normalized protocol value
normalized event -> canonical signing bytes -> Ed25519 verify
exact event bytes -------------------------> stable fingerprint
```

The implementation rejects unknown or ambiguous forms before storage or policy
code sees them.
