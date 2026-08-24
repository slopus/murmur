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

`verify.yml` runs on every `main` push and pull request. It verifies the local
source tree and then exercises the permanently deployed Cloudflare staging
relay with the repository's protected staging token secret. Fork pull requests
run the local checks without receiving that secret. The release workflow runs
the same staging gate before publishing.
