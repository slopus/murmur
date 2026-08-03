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
returned method and headers to transfer bytes directly. Blob downloads consume
the Fetch stream incrementally, enforce the optional exact ciphertext length,
and verify the SHA-256 ID before returning bytes. External object links require
HTTPS, contain no URL credentials, and cannot name an explicit
loopback/private-network address; relative same-relay links remain available
to local backends.

`DEFAULT_RELAY_URL` names the public Murmur deployment. Applications still
construct transports explicitly, so choosing a private relay remains a
deliberate one-line change.

## Ephemeral low-latency path

Alongside the durable topic routes, a relay may offer a non-durable stream for
realtime frames. `RelayTransport` gains two **optional** methods so existing
implementations keep compiling, and `HttpRelayTransport` implements both with
`fetch` alone:

```text
publishEphemeral -> POST /v1/topics/:topic/ephemeral   (application/octet-stream)
                    <- { "delivered": <local subscribers> }

openStream       -> GET  /v1/topics/:topic/stream       (text/event-stream)
                    <- ready | frame | wake | drop  events, ": keepalive" comments
```

`publishEphemeral` returns the relay's informational subscriber count; nothing is
stored, retried, or acknowledged. `openStream` reads `response.body`
incrementally and parses the SSE framing itself: lines split on `\n` (tolerating
`\r\n`), `:` comment lines and unknown event names are ignored, `data:` payloads
carry base64url frames or one line of JSON, and events end on a blank line. The
pending line, the retained event name, and the accumulated event data are bounded
together at 256 KiB — comfortably above one base64url-encoded 128 KiB frame. Every
line is measured before it is decoded or retained, including one that arrives
whole inside a single chunk, so a runaway line or event fails the stream instead
of being decoded or buffered without bound. The returned promise resolves when the stream ends or
its `AbortSignal` aborts, rejects on transport failure, and never leaks the
reader. `MAX_RELAY_EPHEMERAL_FRAME_BYTES` (128 KiB) is the frame ceiling.
