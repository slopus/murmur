# Welcome

RFC 9420 `Welcome`, `EncryptedGroupSecrets`, `GroupSecrets`, and `GroupInfo`
for cipher suite `0x0001`.

This profile supports the per-member common-ancestor path secret used by
TreeKEM Commits, but not PSKs. The ratchet tree is provided over an
authenticated external channel, as allowed by RFC 9420, and is validated
through a mandatory callback before join. That callback must verify the tree
hash, parent hashes, `GroupInfo` signer, and presence of the joining KeyPackage
leaf.

```text
winning Add Commit
   +-- per-joiner path secret -> HPKE(KeyPackage init key)
   +-- next GroupInfo -------> encrypted by welcome_secret
   `-- authenticated tree ---> external invitation channel
joining bundle -> open secrets -> verify GroupInfo/tree -> derive epoch E+1
```

Successful adoption consumes the KeyPackage init secret; any verification
failure leaves the durable bundle available for the actual winning invitation.
