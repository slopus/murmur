# Chaos testing

Deterministic fault-injection boundaries for Murmur's durable store, delivery
transport, and clock. The module is package-internal test infrastructure: it is
compiled and typechecked with Murmur but is not exported from the published
package root.

Faults are selected from redacted operation metadata. Store values, delivery
ciphertext, signatures, and secret key bytes never enter a chaos trace.

```text
seed + exact rules -> schedule -> store / transport boundary
                           |
                           `-> redacted replay trace

virtual clock ---------> production `now` callbacks
```

## Exports

- `SeededRandom` — platform-independent deterministic 32-bit random source with
  actor-independent labeled forks.
- `SeededChaosSchedule` — exact and seeded fault rules with consumption checks
  and redacted traces.
- `ManualVirtualClock` — monotonic, synchronous virtual millisecond clock.
- `FaultInjectingMurmurStore` — `MurmurStore` wrapper with transaction cut
  points, lost-response faults, and defensive byte copying.
- `FaultInjectingDeliveryTransport` — `DeliveryTransport` wrapper for request
  loss, response loss, delay, duplication, page mutation, and stream faults.
- `ChaosInjectedError` and `ChaosCrashError` — typed sentinels for injected
  failures and simulated process loss.
- `settleChaos` — bounded deterministic convergence driver for scenario tests.
- Types for points, effects, schedules, traces, selectors, rules, clocks, and
  wrapper options.

Fault rules must be followed by `assertConsumed()` in tests. This prevents a
passing test when a target cut point silently moved or was never exercised.
