# Client implementation tests

Tests for the helpers inside `client/impl` that are not visible from the client's
public surface.

`topicStream.test.ts` covers `backoffDelay`, the reconnect schedule behind
`MurmurClient.openTopicStream`:

```text
attempt n -> window [250 * 2^n, 250 * 2^(n+1))  capped at 15 s
```

It asserts that the first attempt spans a real range rather than one fixed
delay — a constant would make every client reconnect in lockstep after a relay
blip — that later windows grow and saturate at the ceiling, and that negative,
huge, and non-integer-sized attempts stay inside the 250 ms / 15 s bounds.
