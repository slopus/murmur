# Node server tests

These tests drive the real Node server request listener with Node request and
response objects, then emit the premature close event used for disconnected
clients. This verifies lifecycle behavior without binding a network port.

```text
HTTP client -> Node adapter -> Fetch AbortSignal -> relay long-poll waiter
```

`shutdown.test.ts` is the exception: it binds an ephemeral loopback port,
because an open SSE response only exists over a real socket. It holds one stream
open and checks that shutdown stays pending until the service closes its
streams, then finishes with an orderly end of stream, and that a stream nobody
closes is destroyed once the grace period expires.
