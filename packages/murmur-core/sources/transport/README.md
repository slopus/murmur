# Transport

Browser-safe client boundary for the fixed dumb-relay protocol. A topic has a
snapshot, a permanent ordered list, and a bounded retained event log. Events are
Ed25519-signed canonical JSON; opaque bytes use unpadded base64url on HTTP.

```text
signed event -> /v1/topics/:topic/events
                       |
             +---------+----------+
             |         |          |
          snapshot    list    bounded log
```

`HttpRelayTransport` supports an injected Fetch implementation, so browsers,
workers, and in-process test relays use the same code without a TCP socket.
Blob IDs remain SHA-256 hashes of ciphertext. `putBlob` and `getBlob` hide the
two-step transfer: request a short-lived link from the relay, then use the
returned method and headers to transfer bytes directly.
