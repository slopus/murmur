# Sessions

The stateful public MLS layer. Two-person and many-person interactions use the
same opaque session primitive.

```text
32-byte digest -> discovery bundle -> sealed Welcome -> pending -> activate
                                             |
identity inbox -> MLS event / Commit -> role-validated current checkpoint
       |                          |                    |
       +---- UUIDv7 arbitration -+---- update index --+
                                                        |
                                         one identity-wide onUpdates batch
```

Relay queues are delivery buffers. Session checkpoints, outboxes, replay state,
pending decisions, and bounded opaque buffers live in the application-supplied
transactional store.

`MurmurClient.sync({ ... })` maintains one signed SSE connection, processes
exact queue events through the durable inbox boundary, reconnects from the
local cursor, and wakes on locally queued outboxes. Application events from all
active sessions enter one UUIDv7-ordered index. Contact handling and registered
service callbacks run inside that same cycle. Global `onUpdates` receives
service-owned updates with their stable service ID; Murmur atomically removes a
whole batch only after every relevant callback resolves. `synchronize()`
remains the bounded foreground alternative.

Every inbox delivery has a per-inbox sequence and loss generation. A gap or
generation change first persists one stable `MurmurResetEvent` containing the
complete session snapshot. `onReset` is retried with that same event until it
resolves. Murmur then commits one purge of all session, MLS, outbox, intent,
buffer, replay, and transport state while retaining device identity, account
signing material, credential, rosters, contacts, and profiles. The transaction
adopts the relay's observed head as the new baseline and queues the signed
roster reset announcement. Recreated sessions keep their descriptors and expose
`reAdmission: true`; application history backfill remains application-owned.

Every session epoch authenticates one immutable owner account, an admin set,
and the `adminsAssignAdmins` and `anyoneCanAddMembers` policies. Public
membership and role mutations first persist bounded asynchronous intents. Any
authorized current member may create a Commit; the first valid shared relay
event ID for an epoch wins, while losing staged work is rebased and retried.
There is no session-level committer role or retained proposal queue.
