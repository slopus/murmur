# Group implementation

Internal conversion from Murmur's signed KeyPackage profile to the exact public
LeafNode representation authenticated by the initial ratchet tree.

```text
creator KeyPackage LeafNode
          |
          +-- preserve credential/signature/encryption key
          `-- change source context -> epoch-zero ratchet-tree leaf
```

This conversion ensures the initial tree authenticates the same identity and
keys that the creator advertised in its KeyPackage.
