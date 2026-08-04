# Relay implementation

Process-local and Postgres notification wake sources reduce long-poll latency.
They never carry event payloads or authorization secrets.
