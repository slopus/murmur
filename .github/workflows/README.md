# GitHub workflows

```text
vX.Y.Z tag
    +-- verify repository and package compatibility
    +-- publish @slopus/murmur to npm
    +-- publish multi-architecture relay image to GHCR
    `-- create the GitHub Release
```

`publish.yml` is intentionally tag-driven. The tag must exactly match the
version in `packages/murmur/package.json`.

npm publication uses trusted publishing. The `publish-library` job requests an
OIDC token from the `npm` environment, so npm mints a short-lived credential
and attaches provenance itself; there is no npm token in this repository. The
trusted publisher registered for `@slopus/murmur` must name this repository,
`.github/workflows/publish.yml`, and the `npm` environment exactly, or the
publish fails with a 404.

`verify.yml` runs on every `main` push and pull request. It verifies the local
source tree and then exercises the permanently deployed Cloudflare staging
relay with the repository's protected staging token secret. Fork pull requests
run the local checks without receiving that secret. The release workflow keeps
its tag gate short: ordinary unit tests, static checks, and package compatibility.
Integration, staging, and chaos suites are opt-in and do not run during release.
