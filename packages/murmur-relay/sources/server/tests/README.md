# Node server tests

These tests drive the real Node server request listener with Node request and
response objects, then emit the premature close event used for disconnected
clients. This verifies lifecycle behavior without binding a network port.

```text
HTTP client -> Node adapter -> Fetch AbortSignal -> relay long-poll waiter
```
