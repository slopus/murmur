# `@murmur/mls`

Murmur's browser-safe path toward RFC 9420.

The implementation is built in conformance layers:

1. RFC 9180 HPKE and MLS cipher suite `0x0001`.
2. RFC 9420 encoding, labeled KDF/signatures, key schedule, and ratchet-tree
   math.
3. KeyPackage, Welcome, Proposal, Commit, and application-message state.

The package now includes authenticated PublicMessage Commits with inline Add
and Remove proposals, RFC TreeKEM public-tree validation, UpdatePath
creation/opening, Welcome path-secret delivery, epoch-zero creation,
forward-secret durable epoch checkpoints, and transactional relay publication.

Official RFC 9180 HPKE and MLS working-group ratchet-tree/UpdatePath vectors
exercise the available interoperable layers. This remains an RFC subset rather
than a complete general-purpose MLS implementation: PSKs, external Commits,
proposal references, Update proposals, and arbitrary extensions are outside the
Murmur profile. Code only claims RFC behavior implemented and tested in that
layer. A Murmur-specific application protocol is never labeled MLS.
