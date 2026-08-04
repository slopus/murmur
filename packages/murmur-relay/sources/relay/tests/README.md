# Relay service tests

Policy tests use owned SQLite and PGlite stores. They protect signatures,
one-sided future-skew and expiration enforcement, offline first publication,
pre-crypto size rejection, long-poll wakeup, overload, the register/recheck race
closure, and age-independent durable retries.

```text
signed publish -> SQLite :memory: -> ordered read
bad author/time/size -----------------> reject before persistence
park read <---- publish/wake ----------> returns without missed event
duplicate exact ID -------------------> idempotent outcome
```

Using the real owned store keeps policy tests aligned with production sequence
and idempotency behavior.
