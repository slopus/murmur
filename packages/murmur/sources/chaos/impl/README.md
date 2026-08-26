# Chaos implementation

`seededSchedule.ts` owns deterministic random choices, exact rule matching,
redacted traces, typed fault errors, and bounded settling.
`virtualClock.ts` owns monotonic virtual time.
`faultInjectingStore.ts` instruments the public `MurmurStore` boundary.
`faultInjectingTransport.ts` instruments the public `DeliveryTransport`
boundary without replacing relay semantics.

All helpers are browser-safe and use no global randomness or real-time sleeps.
