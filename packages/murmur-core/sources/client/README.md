# Client

`MurmurClient` combines an identity, a transactional store, and one or more
relays. Publishing succeeds after at least one relay accepts the signed event.
The durable outbox remembers remaining relays; identical retries use the
relay's original sequence and `duplicate` outcome.

```text
relay event page -> authenticate -> application transaction
                                      |             |
                                application state  cursor
```

Following a topic is local only; relays keep no subscription records. Each
relay/topic cursor is durable because relay sequence numbers are local to that
relay. `ReceivedEvent.advanceCursor(transaction)` must run in the same
`MurmurStore` transaction as the application effect and rejects sequence gaps.

`sync()` returns a discriminated result. When any event page says `reset: true`,
the result is `status: "reset"` and contains no events. The caller must use
`loadTopic()` to apply the permanent snapshot and fully paginated list and
install their head cursor atomically. Reset can therefore never look like
"caught up."
