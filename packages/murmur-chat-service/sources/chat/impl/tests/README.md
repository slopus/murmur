# Implementation tests

These tests exercise strict binary bounds and attachment security mechanics
without weakening the public surface.

```text
source -> encrypt -> hostile BlobStore -> authenticate -> plaintext
                    ^ mutation tests at every boundary
```
