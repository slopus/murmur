# Relay source

The package is split by the boundary each piece owns:

```text
HTTP request -> relay policy -> storage transaction
                    |                |
                 protocol       SQLite/Postgres
```

- `protocol` defines and authenticates the relay's own opaque wire format.
- `relay` applies limits, timestamp policy, retention, and long-poll behavior.
- `storage` contains the single persistence contract and its two implementations.
- `http` exposes the Fetch-compatible API.
- `server` adapts that handler to Node's HTTP server.
- `utils` contains strict codecs which do not know relay semantics.

`index.ts` is the library entry point. `main.ts` is the standalone executable.
