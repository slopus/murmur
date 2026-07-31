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
Blob IDs remain SHA-256 hashes of ciphertext.
