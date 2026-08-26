# Package tests

Cross-domain tests exercise the public package surface. Tests for one domain
stay in that domain's own `tests` directory.

```text
built package exports
    +-- imported by Node
    `-- bundled by esbuild for a browser
```

The package test proves that the root contains only the facade runtime exports
and bundles for browsers without Node imports. MLS is compiled internally and
has no package subpath.

`vitestReporterProxy.ts` is not a test. Both vitest configurations load it as a
worker setup file so a test that holds the event loop in synchronous
cryptography does not expire Vitest's reporter acknowledgement.

`stagingRelay.e2e.ts` always targets the public Cloudflare staging Worker. It
checks health, invalid-ticket rejection, authenticated multicast, duplicate
publication, inbox order, device binding, acknowledgement, streaming, and
reconnect redelivery. Run it with `pnpm test:staging`; the signing capability is
provided only through `MURMUR_RELAY_STAGING_TOKEN_SECRET`.
