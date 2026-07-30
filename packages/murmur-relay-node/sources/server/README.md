# Node server

Streaming adapter from Node's built-in HTTP server to the runtime-neutral Fetch
relay handler. The executable defaults to `0.0.0.0:8787` and
`./data/murmur-relay.sqlite`, configurable with `HOST`, `PORT`, and
`MURMUR_RELAY_DB`. Set `MURMUR_RELAY_ORIGINS` to a comma-separated browser
origin allowlist; the default `*` is suitable because Murmur authenticates
protocol requests with signatures rather than cookies.
