# Packages

- `murmur` — `@slopus/murmur`, the browser-safe published library for durable
  MLS sessions, account synchronization, and authenticated delivery queues.
- `murmur-relay` — private standalone and Cloudflare relay infrastructure.
- `murmur-site` — private static product site.

The library owns cryptographic and durable client state. The relay owns only
bounded opaque pending delivery and acknowledgement state.
