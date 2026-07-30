# Fetch relay handler

The default relay protocol as a standard Fetch handler. Cloudflare Durable
Objects can call it directly; Node hosts adapt an incoming request to `Request`.

All cryptographic validation stays in `RelayService`. This module only bounds
and decodes HTTP bodies, maps routes, and encodes responses.
