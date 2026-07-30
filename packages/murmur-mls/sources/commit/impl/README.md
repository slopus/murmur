# Commit encoding internals

Strict codecs for RFC 9420 PublicMessage Commits. The compatibility codec covers
partial Add-only Commits; the full codec preserves ordered inline Add/Remove
proposals and a mandatory UpdatePath.
