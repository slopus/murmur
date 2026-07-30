# Client

`MurmurClient` combines one identity, durable storage, and one or more
transports. It fans outgoing events and blobs across relays, merges duplicate
deliveries, and exposes manual acknowledgement.

```text
             relay A ----\
identity -> MurmurClient ---> one ordered batch -> application -> ack
             relay B ----/          |
                               durable dedupe
```

An unacknowledged event may be delivered again after process restart. Once the
application acknowledges it, every future duplicate is suppressed and its relay
copy is acknowledged. This is the only lossless form of exactly-once processing
possible without pretending that application state and relay state share one
transaction.

Applications which need their own durable event mapping can create a signed
`RelayEvent` first and pass it to `publishEvent()`. Repeating the same event
resumes its retained relay acceptance state. `retryOutboundSettled()` isolates
individual failures so one offline relay record never blocks later retries or
incoming synchronization.
