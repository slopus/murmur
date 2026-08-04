# Client

`MurmurClient` combines one identity, one application-provided transactional
store, and exactly one relay transport. `publish(access, payload)` signs a
`Read Topic` write with the client identity and a protected write with the
shared `writeSecretKey` after verifying it matches the descriptor. It follows
typed topics and persists one cursor per topic.

`ReceivedEvent.advanceCursor(transaction)` belongs in the same transaction as
the application effect. Cursor advancement accepts holes caused by expiration
and collapse. The client deliberately contains no chat protocol, multi-relay
ordering, failover, or hidden retry queue.

Event pages explicitly report `exhausted`. A final event advances to the topic
head only when no retained successor remains; byte-truncated pages therefore
cannot skip an event.
