# Relay implementation helpers

`deliveryValidate.ts` enforces canonical identity, recipient, time, signature,
ciphertext, and fanout bounds before storage. `wakeHub.ts` closes long-poll
registration races and keeps waiter cardinality bounded.
