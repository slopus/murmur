# Directory implementation

The local Ed25519 issuer is intended for tests and local deployments. Production
authentication servers can provide any verifier implementing the public seam.

Tickets are canonical JSON signed under a directory-specific domain and remain
opaque bytes at the HTTP boundary. SQLite or PostgreSQL, rather than the
verifier, atomically accounts the ticket's claim budget.
