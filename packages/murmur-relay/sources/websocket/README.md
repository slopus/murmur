# WebSocket relay transport

This additive boundary maps temporary device-bound tickets and strict JSON
WebSocket frames onto the existing relay service. HTTP/SSE routes remain
unchanged.

Queue pages and acknowledgements carry the same sequence and generation fields
as HTTP. A stream emits one continuity control frame before delivery frames, so
the client proves the chain before processing ciphertext. Connected streams may
also receive an ephemeral `device_roster_changed` invalidation naming their
account; clients fetch the authoritative roster before using it.

The same strict request frame carries account-signed `delete_session` and
`delete_account` operations plus roster read/mutation and directory upload/claim
operations. Account-signed control work is not bound to the device ticket used
only to reach the relay; signatures, current roster state, and directory tickets
provide operation-specific authorization.
