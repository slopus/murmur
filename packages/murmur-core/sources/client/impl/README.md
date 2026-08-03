# Client implementation

Wire-independent persistence codecs for signed relay events and bounded outgoing
history.

`topicStream.ts` holds `TopicStreamController`, the non-durable multi-relay
stream returned by `MurmurClient.openTopicStream`. It runs one reconnect loop per
stream-capable relay, tags every forwarded event with its relay id, and uses a
cancellable backoff timer so `close()` stops each loop without leaving a pending
reconnect scheduled. Every application handler is invoked through `notify`, which
swallows its failure: a throwing handler must never break the reconnect loop it
is called from or surface as an unhandled rejection. `backoffDelay` jitters every
attempt across a real window — `[250 * 2^n, 250 * 2^(n+1))`, capped at 15 s — so
relays that all drop at once do not retry in lockstep.
