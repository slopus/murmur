# Client

`MurmurClient` combines one identity, one application-provided transactional
store, and exactly one relay transport. It signs opaque events, follows typed
topics, and persists one cursor per topic.

`ReceivedEvent.advanceCursor(transaction)` belongs in the same transaction as
the application effect. Cursor advancement accepts holes caused by expiration
and collapse. The client deliberately contains no chat protocol, multi-relay
ordering, failover, or hidden retry queue.
