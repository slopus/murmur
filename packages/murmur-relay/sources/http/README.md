# HTTP API

The Fetch-compatible handler can be tested without binding a socket. It performs
strict routing, incrementally bounds request bodies, converts base64url at the
protocol boundary, and serializes every bigint as a decimal string.

```text
Request -> bounded body/query decode -> RelayService -> JSON/octet response
```

CORS defaults to `*` and can be restricted to an explicit origin list. Event and
list encoders accumulate UTF-8 sizes and stop at the configured response budget,
while preserving the topic head or next list cursor needed to continue.
