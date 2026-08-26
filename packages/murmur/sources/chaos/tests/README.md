# Chaos infrastructure tests

Fast self-tests prove deterministic seeds, isolated forks, virtual time,
transaction rollback versus lost responses, defensive copying, transport
idempotence, page mutation, acknowledgement retry, rule consumption, redaction,
bounded settling, terminal-operation forwarding, and abort behavior.

Session fault campaigns use bare one-use KeyPackage material.

These files use the `.chaos.ts` suffix and run through the chaos-only Vitest
configuration, not the normal unit-test glob.
