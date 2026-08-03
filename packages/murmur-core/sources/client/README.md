# Client

`MurmurClient` combines an identity, a transactional store, and one or more
relays. Publishing succeeds after at least one relay accepts the signed event.
The durable outbox remembers remaining relays; identical retries use the
relay's original sequence and `duplicate` outcome.

`replaceOutboundEvent()` is the narrow freshness escape hatch for higher-level
protocols with stable logical IDs. It atomically swaps a retained event for a
newly signed event only when topic, author, payload, snapshot, and list
operations are identical; only event ID, creation time, and signature may
change.

`relayIds` exposes the configured relay order. `putBlobToRelay()` and the
optional relay target argument on `publishEvent()` and `replaceOutboundEvent()`
let a higher-level protocol make a blob durable on one relay before publishing
the event that references it there. Targeted publication still updates the same
durable event outbox, so ordinary retry later covers the remaining relays.

`publishEventToRelay()` instead performs one validated relay write without
entering that generic retry queue. It is only for higher-level engines such as
DirectChat that already persisted the exact event and per-relay progress; this
keeps generic retries from bypassing protocol-specific prerequisites.

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

## Ephemeral streams

`publishEphemeral()` and `openTopicStream()` ride the relay's non-durable
low-latency path. Neither touches the store: no outbox, no cursors, no retention.

```text
publishEphemeral -> fan out to every stream-capable relay -> sum of delivered
openTopicStream  -> one live stream per capable relay, each with its own backoff
                      onFrame / onWake / onDrop / onStatus  (tagged by relayId)
```

`publishEphemeral()` resolves with the total delivered count and throws only when
every capable transport failed. `openTopicStream()` returns a `TopicStream` that
connects to every transport implementing `openStream`, reconnects each relay with
bounded exponential backoff plus jitter (250 ms floor, 15 s ceiling, every attempt
spread across a real range so relays never retry in lockstep), and reports
per-relay connection state through `onStatus`. Frames pass straight through — the
client buffers nothing — and `close()` aborts every connection and guarantees no
further reconnect timer is scheduled. Both calls throw when no configured
transport implements the matching optional method, so a misconfigured relay set
fails loudly instead of yielding a stream that can never connect. A handler that
throws is isolated: it cannot stop a relay from reconnecting.
