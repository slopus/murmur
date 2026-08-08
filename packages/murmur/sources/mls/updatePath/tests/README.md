# UpdatePath tests

Creator/receiver agreement, excluded-member rejection, tamper handling, cleanup,
wire round trips, and official TreeKEM vectors.

```text
committer path secret -> encrypt to copath resolutions
retained receiver ----> decrypt one path secret -> derive same root
excluded receiver ----> no ciphertext/private path -> cannot advance
tampered node/ciphertext -------------------------> reject + cleanup
```

Official vectors anchor the local tree-index and HPKE implementation to RFC
TreeKEM behavior.
