# CLI runtime

The runtime owns one durable identity, local SQLite state, pairwise chats,
encrypted attachments, MLS groups, and shared documents over fixed-contract
relays.

```text
public inbox event -> authenticated contact + cursor
pairwise list/event -> message/replay marker + cursor
group event -> MLS checkpoint/application + cursor
```

Contact requests seal their sender identity and use one-use relay authors on the
public first-contact inbox. Once a profile is authenticated, direct messages and
invitations use the X25519 pairwise topic. Text messages use core `DirectChat`
for exact pending retries, authenticated topic binding, atomic replay/cursors,
and recipient plus self permanent-list copies. A fresh CLI store can therefore
reconstruct both directions exactly once after the event log expires. Local
history remains the application view.

All inbound success paths update application state and the relay/topic cursor
in one SQLite transaction. Invalid input is quarantined with that cursor in the
same transaction. Deferred MLS values do not advance. A relay `reset` is raised
as an explicit state-reload error rather than reported as an empty sync.

The legacy attachment send path remains wire-compatible until the dedicated
attachment-engine task; all incoming direct envelopes already use the one core
engine acceptance path.

MLS publication keeps exact durable outboxes and the
prepare → persist → publish → adopt ordering. Ambiguous publication remains
staged. The in-process end-to-end test uses one `SqliteRelayStore(":memory:")`
and injected Fetch, exercising profiles, an attached direct message, offline
text delivery, pending restart retry, pruned-log full bidirectional recovery,
group invite/message/removal, and document convergence without a TCP socket.
