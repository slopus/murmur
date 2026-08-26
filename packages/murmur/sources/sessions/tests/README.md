# Session tests

Integration tests use the real in-memory relay and real low-level MLS
cryptography. They cover bootstrap, pending activation, opaque event delivery,
restart, one-use bare KeyPackages, directory claims, reusable fallback
Welcomes, membership changes, and bounded state.

Account deletion coverage drops the first relay confirmation, retries the same
durable request through replay detection, and proves the client clears every
local key only after relay acceptance.
