# Epoch key schedule

RFC 9420 joiner, member, and epoch secret derivation for cipher suite `0x0001`.
Every returned secret is an independent mutable array so callers can zero it
when advancing the epoch.
