# Crypto

Identity signatures use Ed25519. Pairwise sealed boxes use ephemeral X25519,
HKDF-SHA-256, and AES-256-GCM. Public operations are in `index.ts`; key
derivation and box mechanics are in `impl`.

MLS uses a separate RFC 9420 module built on the suite-specific primitives; the
generic sealed box here is not presented as MLS.
