# Cloudflare adapter tests

The in-memory Durable Object harness checks strict internal JSON boundaries,
manifest-first sequencing, partial fanout retry, alarms, and idempotent
per-device inbox insertion. It also pins the explicit unsupported response for
terminal account deletion in this queue-only adapter.
