# Session implementation

`sessionEngine.ts` coordinates durable state and relay delivery.
`sessionFrames.ts` owns strict bootstrap, PrivateMessage, and Commit envelopes.
`sessionRecords.ts` owns current checkpoints, outboxes, and bounded buffers.
