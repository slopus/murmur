# UpdatePath encoding internals

Strict RFC codec for commit-source LeafNode, parent public keys, and vectors of
HPKE-encrypted path secrets.

```text
UpdatePath
  +-- commit-source LeafNode
  `-- PathNode[]
        +-- parent HPKE public key
        `-- encrypted path secret per copath resolution member
```

The codec keeps recipient ciphertext order aligned with filtered tree
resolution so each retained member selects the intended HPKE value.
