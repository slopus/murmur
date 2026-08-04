# Ratchet-tree encoding internals

Strict codec for the RFC `ratchet_tree` extension: a vector of optional leaf or
parent nodes. Leaf bytes are preserved exactly for tree-hash computation.

```text
public tree array
  index 0: leaf
  index 1: parent
  index 2: leaf/blank ...
          |
optional node tags + exact LeafNode bytes -> ratchet_tree extension
```

Preserving blanks and original leaf encodings is essential because both affect
resolution and the authenticated tree hash.
