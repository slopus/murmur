# Shared-session tests

These tests exercise the published owner/member API over real MLS epochs and a
small in-process opaque relay transport. They cover canonical opaque entries,
batch membership, authenticated posts, encrypted history backfill, restart,
dedupe/collision, and owner-only Commit enforcement.
