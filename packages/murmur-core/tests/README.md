# Package tests

Cross-domain tests exercise the public package surface. Tests for one domain
stay in that domain's own `tests` directory.

```text
built package exports
    +-- imported by Node
    `-- bundled by esbuild for a browser
```

The compatibility test covers every public ESM subpath, including the MLS
implementation copied into the published package during the build.
