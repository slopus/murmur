# UpdatePath

RFC 9420 TreeKEM path generation, public-tree merge, HPKE distribution, private
path derivation, and commit-secret calculation.

```text
fresh secrets -> parent keys -> parent hashes -> signed leaf
             -> provisional tree hash -> HPKE path ciphertexts
```

Creation derives the sender metadata from the authenticated current tree.
Opening conservatively requires the new commit-source leaf to retain and prove
possession of the current sender signature key; signature-key rotation is left
to a future authenticated Update-proposal path.

Welcome joiners reconstruct their private direct path from the delivered
common-ancestor path secret. Every derived private key is matched against the
authenticated public tree before it can be adopted.
