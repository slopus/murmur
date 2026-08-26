# MLS Welcome

Welcome processing authenticates group information, resolves the matching
one-use KeyPackage bundle, decrypts the joiner secret, verifies the ratchet
tree, and derives the initial local epoch.

The session facade persists a received Welcome as bounded pending state before
acknowledging queue progress. Failed or losing bootstrap attempts leave the
private bundle available only when safe for a later valid attempt.
