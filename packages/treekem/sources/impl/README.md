# TreeKEM internals

This directory contains the mechanics hidden by the byte-oriented public API.

```text
codec <-> protocol -> tree
              |
              `----> RFC 9180 HPKE and RFC-style key derivation
```

- `bytes.ts` provides strict fixed-width binary helpers.
- `crypto.ts` owns Noble-based HPKE, signatures, hashes, and derivation.
- `tree.ts` owns the public ratchet tree, resolutions, and unmerged leaves.
- `codec.ts` validates the opaque state, update, and Welcome formats.
- `protocol.ts` implements the stateless public transformations.

No module performs I/O or retains state between calls.
