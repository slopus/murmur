# Relay source

- `protocol` authenticates topic descriptors, writes, and read proofs.
- `relay` enforces capability policy, limits, expiration, and long polling.
- `storage` supplies SQLite and Postgres ordered-event stores.
- `http` exposes the Fetch API.
- `server` adapts Fetch to Node HTTP.
- `utils` contains strict codecs and logging helpers.

```text
Node socket -> server -> Fetch HTTP -> RelayService -> ordered storage
                           |              |
                     protocol codecs   wake sources
                           |
                    opaque signed events
```

The dependency direction keeps event semantics out of the relay while allowing
the HTTP and storage implementations to be tested in process.
