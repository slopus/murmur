# Private-group state tests

End-to-end state-service tests live with the internal browser-safe client in
`packages/murmur/sources/privateGroupState/tests`. They run this real SQLite
service in memory and use the real private-group credential implementation.

The relay-local conformance suite exercises the clean Postgres/PGlite schema,
monotonic canonical UUIDv7 writes, exact retry idempotency, and one-use
challenge consumption.
