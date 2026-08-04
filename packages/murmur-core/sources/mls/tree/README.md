# Ratchet tree

Index arithmetic for the RFC 9420 left-balanced binary tree. Leaves occupy even
node indices. The module exposes direct paths and copaths without owning key
material.

```text
          7
       /     \
      3       8
    /   \
   1     5
  / \   / \
 0   2 4   6
```

The diagram is the five-leaf tree (`8` is the rightmost leaf).
