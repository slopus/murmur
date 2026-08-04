# Relay implementation

Process-local and Postgres notification wake sources reduce long-poll latency.
They never carry event payloads or authorization secrets.

```text
publish commit -> wake(topic ID)
                   +-- process-local waiter registry
                   `-- Postgres LISTEN/NOTIFY
long poll <--------- signal, then re-read authoritative storage
```

Notifications are hints only; the ordered store remains the source of truth
when signals are duplicated or lost.
