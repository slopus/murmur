# Relay source

The package is split by the boundary each piece owns:

```text
HTTP request -> rate limit -> relay policy -> storage transaction
      |
      +-> blob link backend -> local stream / S3 presigned URL
```

- `protocol` defines and authenticates the relay's own opaque wire format.
- `relay` applies limits, timestamp policy, retention, long-poll behavior, and
  the in-process ephemeral (SSE) frame fan-out.
- `storage` contains the single persistence contract and its two implementations.
- `blobs` issues direct transfer links and owns local/S3 blob mechanics.
- `rate-limit` defines the replaceable limiter and bounded in-memory default.
- `http` exposes the Fetch-compatible API.
- `server` adapts that handler to Node's HTTP server.
- `utils` contains strict codecs which do not know relay semantics.

`index.ts` is the library entry point. `main.ts` is the standalone executable.
