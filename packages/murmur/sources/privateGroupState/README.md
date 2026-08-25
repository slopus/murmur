# Private-group state client

This internal module is the sole composition boundary between anonymous
private-group credentials and account-aware MLS sessions. It is deliberately
not re-exported from the published package entry point.

```text
MurmurSession.members (logical accounts)
                 |
group master secret -> deterministic encrypted entries -> canonical record
                 |                                      |
                 `-> encrypted attributes + MLS digest  `-> state service
```

Each device supplies the stable `MurmurClient.accountKey`, so every device of
one account reconstructs the same logical entry while remaining an independent
MLS leaf. The client checks that the canonical encrypted roster is exactly the
set of logical accounts in the authenticated MLS session snapshot. It rejects
unauthenticated records, revision forks, rollbacks, gaps, and membership
changes without matching MLS state.

The state service learns opaque identifiers, entry ciphertexts, fixed roles,
revision metadata, cardinality, timing, and sizes. It does not receive group
secrets, account keys, MLS session identifiers, or plaintext attributes. This
does not provide network anonymity. The credential and proof construction
requires external cryptographic audit before production use.
