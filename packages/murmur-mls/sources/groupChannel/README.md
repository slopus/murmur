# Group channel

Transport adapter from an authenticated `MlsEpochState` to the
transport-agnostic `MurmurClient`.

The application owns the single client sync loop and dispatches received events
by topic. Opened and deferred events preserve manual acknowledgement. Deferred
events are not deleted automatically because they may belong to a future epoch.

RFC `PublicMessage` Commits and application `PrivateMessage` values share the
same opaque topic. Commits are authenticated and staged, then exposed through
explicit `adopt()`/`cancel()` controls so callers can durably persist the next
epoch before acknowledging the relay delivery. A staged Commit cannot be
acknowledged before adoption or after cancellation.

Outbound Commit preparation deliberately does not hide publication ordering.
The caller persists the accompanying tree and Welcome, invokes the handle's
`publish()`, then adopts. If publication has an ambiguous network result, the
transition cannot be cancelled or destroyed; it stays staged until Murmur's
retained outbox has been resolved and `confirmPublished()` is called with the
matching successful retry result.

Commit fingerprints are exported and restored with the epoch. This makes the
sender's relay echo and a post-crash redelivery safely acknowledgeable without
trying to apply the same transition twice. Markers are retained until the
application has evidence that every relevant relay delivery was acknowledged,
then explicitly removed with `forgetAppliedCommit()`.
