# Relay source

- `protocol` authenticates topic descriptors, writes, and read proofs.
- `relay` enforces capability policy, limits, expiration, and long polling.
- `storage` supplies SQLite and Postgres ordered-event stores.
- `http` exposes the Fetch API.
- `server` adapts Fetch to Node HTTP.
- `utils` contains strict codecs and logging helpers.
