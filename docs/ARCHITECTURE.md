# Architecture

Murmur separates durable cryptographic state from disposable transport.

```text
application
  | owns effects and MurmurStore
  v
@slopus/murmur
  | signed opaque deliveries
  v
relay
  | one bounded queue per exact public identity
  v
recipient Murmur client
```

## Library boundary

The library owns identity roots, MLS KeyPackages, epochs, pending bootstraps,
membership intents, replay protection, exact outboxes, account synchronization,
and inbox progress. Application updates cross one identity-wide durable
callback boundary. The application owns their meaning and downstream effects.

Account-secret operations are stateless: a generated string plus password wraps
an identity root into one opaque blob, and the application chooses where to
persist it. Murmur retains no password, recovery copy, or server-side reset
state. Unlocking reconstructs the same identity but never reconstructs device
stores or MLS ratchets.

An application send clones and ratchets the active epoch, then persists both
the new epoch and exact unpublished ciphertext before returning. A membership
Commit persists active and staged epochs separately. The sender adopts its own
Commit only from its authenticated queue echo.

Incoming Welcomes become bounded pending sessions. Murmur continues processing
MLS traffic while pending and buffers application bytes without exposing them.
Activation releases the buffer through the ordinary application boundary;
ignore destroys the pending secrets and data.

## Relay boundary

The relay authenticates queue reads and acknowledgements, validates signed
delivery envelopes, atomically fans one event out to exact recipient inboxes,
and retains only unacknowledged unexpired ciphertext. It has no MLS, descriptor,
membership, role, application, or conversation semantics.

UUIDv7 event IDs order deliveries only within one inbox. Signed acknowledgement
is monotonic and separate from delivery. A continuity generation detects a
restored or rolled-back relay database.

The standalone relay supports SQLite and PostgreSQL. The Cloudflare deployment
uses one inbox Durable Object per public identity and a global fanout Durable
Object for manifest-first atomic multicast.

## Services and accounts

Applications may register typed services under stable IDs. A service can claim
new pending sessions and receives its own updates before the global application
batch is prepared.

Device linking creates an authenticated account roster. Account synchronization
uses an internal MLS session, while ordinary sessions continue to expose
account identities instead of individual device leaves.

## Failure boundaries

- Relay publication failure leaves exact durable outboxes for retry.
- Callback failure leaves the exact update batch for retry.
- Terminal malformed queue items are durably rejected so later items proceed.
- Pending sessions and application buffers are strictly bounded.
- Inbox continuity loss records a final application-visible reset snapshot
  before technical state is purged.
