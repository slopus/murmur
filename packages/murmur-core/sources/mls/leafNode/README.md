# LeafNode

Strict RFC 9420 LeafNode encoding for key-package, update, and commit sources.
Unknown GREASE capabilities and extensions are retained while default
capability values forbidden by RFC 9420 are rejected.

```text
LeafNode source
  +-- key_package -> lifetime
  +-- update ------> group ID + leaf index
  `-- commit ------> group ID + leaf index + parent hash
           |
     source-bound signature
```

One codec handles all sources while requiring the source-specific context that
prevents a signed leaf from being transplanted.
