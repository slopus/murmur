# Client implementation

Wire-independent persistence codecs for signed relay events and bounded outgoing
history.

`topicStream.ts` holds `TopicStreamController`, the non-durable multi-relay
stream returned by `MurmurClient.openTopicStream`. It runs one reconnect loop per
stream-capable relay, tags every forwarded event with its relay id, and uses a
cancellable backoff timer so `close()` stops each loop without leaving a pending
reconnect scheduled.
