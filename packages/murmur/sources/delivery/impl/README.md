# Delivery implementation

`deliveryCodec.ts` owns the exact relay-compatible signed wire format.
`deliveryHttpTransport.ts` implements bounded fetch requests and the
recipient-authenticated SSE connection. `deliverySse.ts` strictly parses
heartbeats and exact delivery records with per-event and heartbeat-timeout
bounds. `inboxProcessor.ts` serializes page or stream processing and enforces
durable-before-ack behavior. `storeTransactionStage.ts` isolates tentative
application writes so a terminal handler rejection commits no partial
application effect.

```text
page JSON / SSE <-> HTTP transport <-> InboxProcessor <-> MurmurStore transaction
```
