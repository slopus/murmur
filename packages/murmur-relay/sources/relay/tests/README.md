# Relay service tests

Policy tests use owned SQLite and PGlite stores. They protect signatures,
one-sided future-skew and expiration enforcement, offline first publication,
pre-crypto size rejection, long-poll wakeup, overload, the register/recheck race
closure, and age-independent durable retries.
