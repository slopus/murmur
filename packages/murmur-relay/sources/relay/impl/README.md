# Relay implementation

In-process and Postgres queue wake sources reduce long-poll latency. Wakes carry
only a public identity queue ID and are hints; every wake is followed by an
authoritative transactional queue read.
