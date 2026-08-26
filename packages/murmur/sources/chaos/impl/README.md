# Chaos implementation

`seededSchedule.ts` owns deterministic random choices, exact rule matching,
redacted traces, typed fault errors, and bounded settling.
`virtualClock.ts` owns monotonic virtual time.
`faultInjectingStore.ts` instruments the public `MurmurStore` boundary.
`faultInjectingTransport.ts` instruments the public `DeliveryTransport`
boundary without replacing relay semantics.
`chaosReporterProxy.ts` is the suite's worker setup file; it keeps Vitest task
reporting from expiring while a long chaos scenario runs.

All helpers are browser-safe and use no global randomness or real-time sleeps.
