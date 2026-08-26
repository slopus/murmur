# Delivery implementation

`deliveryHttpTransport.ts` implements the current HTTP/SSE transport, including
strict directory operations plus session and account deletion.
`deliveryNegotiation.ts` signs temporary-session requests and validates routed
WebSocket tickets. `deliveryWebSocketTransport.ts` implements the current
WebSocket framing, including account-signed terminal operations.

`deliveryCodec.ts` owns the exact relay-compatible signed wire format and binds
each sender to the account that owns its outbound relay state.
`deliveryHttpTransport.ts` implements bounded fetch requests and the
recipient-authenticated SSE connection. `deliverySse.ts` strictly parses
heartbeats and exact delivery records with per-event and heartbeat-timeout
bounds. `inboxProcessor.ts` serializes page or stream processing and enforces
durable-before-ack behavior. `storeTransactionStage.ts` isolates tentative
internal handler writes so a terminal classification commits no partial
protocol effect. Consumer code never receives this transaction.

```text
page JSON / SSE <-> HTTP transport <-> InboxProcessor <-> MurmurStore transaction
```
