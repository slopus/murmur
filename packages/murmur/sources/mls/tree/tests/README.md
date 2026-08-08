# Ratchet-tree tests

Known left-balanced shapes and direct-path/copath examples, including incomplete
right subtrees.

```text
leaf count 5:          root
                     /      \
                 full(4)    leaf(4)
direct path --------> parents
copath --------------> sibling subtrees
```

These index-only vectors underpin ratchet-tree resolution without involving
keys or wire codecs.
