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

Its manual dispatch accepts an existing release tag for recovery. Library-only
recovery skips an already-published relay image while retaining GitHub's npm
trusted publishing and provenance.
