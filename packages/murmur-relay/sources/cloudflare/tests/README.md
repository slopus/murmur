# Cloudflare adapter tests

The in-memory Durable Object harness checks the actual sequencing object,
partial fanout failure, alarms, and idempotent per-device inbox insertion.
It also checks clean private-group object pinning, canonical state replacement,
member-index updates, challenge expiry/replay bounds, stateless credential
configuration, and opaque-group ingress routing.
