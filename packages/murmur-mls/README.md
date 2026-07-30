# `@murmur/mls`

Murmur's browser-safe path toward RFC 9420.

The implementation is built in conformance layers:

1. RFC 9180 HPKE and MLS cipher suite `0x0001`.
2. RFC 9420 encoding, labeled KDF/signatures, key schedule, and ratchet-tree
   math.
3. KeyPackage, Welcome, Proposal, Commit, and application-message state.

The package now includes authenticated add-only PublicMessage Commits plus RFC
TreeKEM public-tree validation and UpdatePath creation/opening. Authenticated
Remove proposals and Commit integration with the new TreeKEM state are still
in progress, so this remains an RFC subset rather than a complete MLS
implementation. Code only claims RFC behavior implemented and tested in that
layer. A Murmur-specific group protocol is never labeled MLS.
