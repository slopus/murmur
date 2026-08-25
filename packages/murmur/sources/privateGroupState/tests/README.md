# Private-group state client tests

These tests compose the real credential implementation with a real
`SqlitePrivateGroupStateStore(":memory:")`. They cover anonymous access,
unlinkability, token scope, replay and expiry, canonical revision forks and
rollbacks, and the MLS logical-account roster binding.
