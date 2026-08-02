# GitHub workflows

```text
vX.Y.Z tag
    +-- verify repository and package compatibility
    +-- publish @slopus/murmur to npm
    +-- publish multi-architecture relay image to GHCR
    `-- create the GitHub Release
```

`release.yml` is intentionally tag-driven. The tag must exactly match the
version in `packages/murmur-core/package.json`.
