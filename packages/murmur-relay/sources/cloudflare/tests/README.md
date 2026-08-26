# Cloudflare adapter tests

The Durable Object harness uses `node:sqlite` behind the synchronous Cloudflare
SQL cursor surface. It checks strict internal JSON boundaries, manifest-first
sequencing, partial retry, roster notification, roster-derived session fanout
and role failures, directory one-time spending and fallback, session deletion,
and alarm-retried terminal account inbox cascades.
