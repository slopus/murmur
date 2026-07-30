# Group channel

Transport adapter from an authenticated `MlsEpochState` to the
transport-agnostic `MurmurClient`.

The application owns the single client sync loop and dispatches received events
by topic. Opened and deferred events preserve manual acknowledgement. Deferred
events are not deleted automatically because they may belong to a future epoch.
Durable senders use `prepareSend()`, atomically store its ciphertext and epoch
checkpoint, call `markPersisted()`, and only then publish. An opened delivery
likewise exposes its exact post-open checkpoint and refuses acknowledgment until
the application marks its epoch plus application record as durably committed.

RFC `PublicMessage` Commits and application `PrivateMessage` values share the
same opaque topic. Commits are authenticated and staged, then exposed through
explicit `adopt()`/`cancel()` controls so callers can durably persist the next
epoch before acknowledging the relay delivery. A staged Commit cannot be
acknowledged before adoption or after cancellation.

Outbound Commit preparation deliberately does not hide publication ordering.
The caller atomically persists the exact Commit, Welcome,
`serializeNextEpoch()` bytes, and `persistenceGeneration`, invokes the handle's
`publish()`, then adopts. If publication has an ambiguous network result, the
transition cannot be cancelled or destroyed; it stays staged until Murmur's
retained outbox has been resolved and `confirmPublished()` is called with the
matching successful retry result.

Commit and application ciphertext fingerprints are exported and restored with
the epoch. This makes sender echoes and post-crash redeliveries safely
acknowledgeable without applying a transition twice or reopening a consumed
generation. Markers must be stored in the same transaction as the epoch and
application/outbox record. They remain until the application has evidence that
every relevant relay delivery was acknowledged, then are explicitly removed
with `forgetAppliedCommit()` or `forgetAppliedApplication()`.
