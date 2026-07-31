# Group channel

Adapter from `MlsEpochState` to signed relay topic events. A random group ID
known only to members derives one capability topic shared by every epoch.

Outbound work preserves **prepare → persist → publish**. Application sends
persist their exact ciphertext and post-ratchet checkpoint before publication.
Commits persist the exact Commit, Welcome, replay marker, and staged next-epoch
checkpoint before publication, and are adopted only afterward. A timeout stays
ambiguous and staged until the durable Murmur outbox resolves the exact event.

Inbound statuses retain their protocol meanings: `opened`, `commit`, `applied`,
`application-applied`, `removed`, and `deferred`. Application records, MLS
checkpoints, replay markers, and `advanceCursor(transaction)` belong in one
transaction. A deferred future-epoch value is never advanced automatically.

Persisted commit/application fingerprints make sender echoes and crash replays
idempotent without reopening a consumed MLS generation. Removed members
durably install a tombstone and cursor before live secrets are destroyed.
