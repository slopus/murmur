# Cloudflare implementation

These files use small structural interfaces instead of a runtime dependency on
Cloudflare type packages. The Worker entry imports only browser-safe relay
modules.

The strict request codec recognizes terminal account deletion so this
queue-only adapter can return an explicit unsupported-operation response.
