# Ratchet tree

Public RFC 9420 TreeKEM state. Nodes use the standard array layout and retain
exact encoded LeafNode bytes for stable tree hashing.

External tree decoding requires a credential-authentication callback and
verifies LeafNode signatures, unique keys, unmerged-leaf ancestry, parent-hash
coverage, canonical wire data, and the RFC trailing-blank rule before returning
the tree.

```text
proposals -> candidate tree -> UpdatePath merge -> tree hash
                    |
                    +-> commit / cancel outside the active epoch
```

Private path secrets and UpdatePath encryption are layered on this public state.
