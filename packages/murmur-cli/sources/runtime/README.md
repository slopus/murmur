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
invitations use the X25519 pairwise topic. Messages append ciphertext to the
permanent relay list; local history remains the application view.

All inbound success paths update application state and the relay/topic cursor
in one SQLite transaction. Invalid input is quarantined with that cursor in the
same transaction. Deferred MLS values do not advance. A relay `reset` is raised
as an explicit state-reload error rather than reported as an empty sync.

MLS publication keeps exact durable outboxes and the
prepare → persist → publish → adopt ordering. Ambiguous publication remains
staged. The in-process end-to-end test uses one `SqliteRelayStore(":memory:")`
and injected Fetch, exercising profiles, an attached direct message, group
invite/message/removal, and document convergence without a TCP socket.
