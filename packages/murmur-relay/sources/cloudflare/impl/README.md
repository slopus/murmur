# Cloudflare implementation

These files use small structural interfaces instead of a runtime dependency on
Cloudflare type packages. The Worker entry imports only browser-safe relay
modules.

The strict request codec covers queue work plus account deletion, roster
read/mutation, and directory upload/claim frames. Session fanout and those
control operations are forwarded to the singleton Durable Object, whose
synchronous SQLite state determines authorization and exact recipients.
