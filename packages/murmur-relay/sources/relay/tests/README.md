# Relay service tests

Policy tests use the owned in-memory SQLite store. They protect signature and
timestamp enforcement, pre-crypto size rejection, long-poll wakeup, overload,
the register/recheck race closure, and age-independent durable retries.
