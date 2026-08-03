# Client tests

Multi-relay publication, idempotent retry outcomes, permanent-list loading,
atomic application/cursor commits, and mandatory reset signaling use an
in-process transport double implementing the fixed contract.

`topicStream.test.ts` covers the ephemeral surface with a scripted stream
double: relay-tagged frame forwarding and status reporting, reconnect after a
stream ends, `close()` preventing further reconnects, and `publishEphemeral`
fan-out that sums delivered counts, tolerates a single relay failure, and throws
only when every capable transport fails. It also pins handler failure isolation —
a throwing `onStatus` must not strand a relay's reconnect loop, and throwing
`onFrame`, `onWake`, or `onDrop` handlers must not escape into the transport —
and that `openTopicStream` throws, like `publishEphemeral`, when no configured
transport implements the matching optional method.
