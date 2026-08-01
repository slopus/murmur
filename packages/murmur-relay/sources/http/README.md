# HTTP API

The Fetch-compatible handler can be tested without binding a socket. It performs
strict routing, incrementally bounds JSON request bodies, applies weighted
per-IP and authenticated-author limits, converts base64url at the protocol
boundary, and serializes every bigint as a decimal string.

```text
Request -> client-IP/rate policy -> route -> RelayService or BlobBackend
```

CORS defaults to `*` and can be restricted to an explicit origin list. Event and
list encoders accumulate UTF-8 sizes and stop at the configured response budget,
while preserving the topic head or next list cursor needed to continue.
`X-Forwarded-For` is ignored by default; only an explicit hop-count or exact
proxy-address policy enables it.
