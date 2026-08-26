# MLS

Browser-safe MLS protocol machinery using Noble primitives. Modules cover the
cipher suite, KeyPackages, ratchet trees, group context, key schedule, Welcome,
Commit, UpdatePath, secret tree, private messages, and epoch state.

The MLS layer operates on explicit byte arrays and typed state. The session
facade owns persistence, queue ordering, outboxes, replay, pending activation,
roles, and application effects.
