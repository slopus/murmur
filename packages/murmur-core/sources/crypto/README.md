# Crypto

A Murmur identity publishes exactly one 32-byte Ed25519 public key and owns
exactly one 32-byte root secret. Ed25519 signing uses that root directly.
X25519 agreement converts the Ed25519 root and public point with Noble's
`toMontgomerySecret` and `toMontgomery` operations.

The Ed25519 and X25519 encodings are not raw aliases and no second public key is
part of identity serialization. Sharing one root across these two operations is
a deliberate product choice with the theoretical composition risk accepted in
the friends master plan; this module does not claim a general security proof.
Public identity decoding rejects non-canonical, identity, small-order, and
non-torsion-free Ed25519 points before signing verification or X25519
conversion.

Sealed boxes use ephemeral X25519, HKDF-SHA-256, and AES-256-GCM. Every derived
secret intermediate is zeroed after use.

`encodeIdentityRoot` and `decodeIdentityRoot` provide the strict
application-owned storage representation. It contains only the one root secret;
applications are responsible for protecting those stored bytes.
