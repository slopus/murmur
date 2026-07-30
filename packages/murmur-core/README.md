# `@murmur/core`

Browser-safe Murmur primitives: identities, encrypted profiles, relay transport
contracts, durable client state, and exactly-once event handling.

The package has no Node.js imports. Applications supply persistence and one or
more transports.

```text
application
    |
MurmurClient
    |---- ClientStore
    `---- RelayTransport[]
              |
          dumb relays
```
