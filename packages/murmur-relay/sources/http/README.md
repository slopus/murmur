# HTTP

Fetch-compatible `/v1/deliveries`, `/v1/queue/read`, and `/v1/queue/ack`
endpoints with bounded strict JSON and explicit CORS policy. Authentication is
inside each signed protocol body.

```text
HTTP body -> byte bound -> exact codec -> relay service -> bounded JSON
remote address -----------------------> fixed-window admission bound
```

A remote socket address is mandatory for every non-OPTIONS request by default,
including health checks. The supplied Node host provides it from the
connection; an embedder may disable this requirement only explicitly with
`requireRemoteAddress: false` and must then provide one explicit
`defaultAdmissionPrincipal`; all embedded traffic shares that exact pending
fanout budget. Configure `remoteAddressHeader` only behind a trusted proxy that
overwrites the named header. It may carry a stable authenticated principal
instead of an address. Never trust a client-controlled forwarded header.

The in-process fixed-window limiter bounds request concurrency and accidental
abuse; it does not make self-created protocol identities non-Sybil. Public
deployments must enforce their own principal-level outstanding-fanout budget at
the trusted ingress. The handler hashes the supplied address/principal and the
relay also enforces its configured exact outstanding-reference quota for that
principal.

The Fetch handler speaks HTTP semantics but does not terminate TLS. Production
deployments require TLS at a trusted reverse proxy or load balancer because
signed reads and acknowledgements can be replayed within their timestamp
window.

A queue page uses nullable UUIDv7 `head` and `acknowledgedThrough` cursors. If a
previously accepted delivery is larger than the current response budget, the
relay returns `413 delivery_too_large` with its `eventId` and inbox progress so
the client can durably quarantine that terminal item and advance without
head-of-line blocking.
