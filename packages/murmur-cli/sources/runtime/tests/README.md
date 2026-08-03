# Runtime tests

The end-to-end test wires two durable CLI runtimes to one
`SqliteRelayStore(":memory:")` through `createRelayFetchHandler` and injected
Fetch. It covers two-way profile exchange, a pairwise direct message with an
encrypted attachment, group creation/invitation/message/removal, and a shared
document converging after the second member edits it.

It also takes one sender offline, restarts it with a durable pending text event,
prunes the relay event log, and reconstructs both participants' incoming and
outgoing text history from permanent recipient/self copies. Focused codec
coverage protects deterministic shared-document operation IDs and quota
behavior.
