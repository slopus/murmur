# Delivery implementation

`deliveryCodec.ts` owns the exact relay-compatible signed wire format.
`deliveryHttpTransport.ts` implements bounded fetch requests. `inboxProcessor.ts`
serializes synchronization and enforces durable-before-ack processing.
`storeTransactionStage.ts` isolates tentative application writes so a terminal
handler rejection commits no partial application effect.

```text
protocol bytes <-> HTTP transport <-> InboxProcessor <-> MurmurStore transaction
```
