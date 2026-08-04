# Murmur facade internals

The implementation directory contains strict durable/control codecs and the
mechanical state helpers used by the facade.

```text
public facade (../index.ts)
        |
        v
  engine.ts
  +-- friend bootstrap/control helpers ---> friendProcessing.ts
  +-- ordered MLS group helpers ----------> groupProcessing.ts
  +-- exact outbox + cursor transactions -> persistence.ts
  +-- retry/backoff + cancellation ------> convergenceWorker.ts
  |
  +-- controlCodec.ts
  +-- stateCodec.ts
  `-- topics.ts
```

All codecs are bounded and reject unknown fields. Secret-bearing records remain
inside application-provided persistence.
