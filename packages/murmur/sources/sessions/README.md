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

Every session epoch authenticates one immutable owner account, an admin set,
and the `adminsAssignAdmins` and `anyoneCanAddMembers` policies. Public
membership and role mutations first persist bounded asynchronous intents. Any
authorized current member may create a Commit; the first valid shared relay
event ID for an epoch wins, while losing staged work is rebased and retried.
There is no session-level committer role or retained proposal queue.
