# Sessions

The stateful public MLS layer. Two-person and many-person interactions use the
same opaque session primitive.

```text
32-byte digest -> discovery bundle -> sealed Welcome -> pending -> activate
                                             |
identity inbox -> MLS event / Proposal / Commit -> current checkpoint
                                             |
                                      bounded event buffer
```

Relay queues are delivery buffers. Session checkpoints, outboxes, replay state,
pending decisions, and bounded opaque buffers live in the application-supplied
transactional store.
