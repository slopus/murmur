# Epoch key schedule

RFC 9420 joiner, member, and epoch secret derivation for cipher suite `0x0001`.
Every returned secret is an independent mutable array so callers can zero it
when advancing the epoch.

Epoch zero follows RFC 9420 Section 11 directly: the creator samples the
`epoch_secret`, derives the epoch outputs from it, and has no joiner/member
secret yet.
