# GitHub automation

Repository automation is deliberately release-focused.

```text
.github/
    |
    `-- workflows/
            `-- publish.yml
                  tag -> verify -> package/image -> release
```

The release workflow enforces the root-only npm surface and tests the packed
artifact as an installed TypeScript/browser consumer before publishing.
