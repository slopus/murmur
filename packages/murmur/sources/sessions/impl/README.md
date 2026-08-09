# Session implementation

`sessionEngine.ts` coordinates durable state, relay delivery, and local
KeyPackage retention. Ordinary admission packages are deleted after one
Welcome; contact last-resort packages carry an explicit reusable marker and
remain available for later offline group Welcomes until rotation or expiry.
`sessionFrames.ts` owns strict bootstrap, PrivateMessage, and Commit envelopes.
`sessionRecords.ts` owns current checkpoints, outboxes, and bounded buffers.
