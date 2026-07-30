# Welcome

RFC 9420 `Welcome`, `EncryptedGroupSecrets`, `GroupSecrets`, and `GroupInfo`
for cipher suite `0x0001`.

This profile currently supports no PSKs and no path secret. The ratchet tree is
provided over an authenticated external channel, as allowed by RFC 9420, and is
validated through a mandatory callback before join. That callback must verify
the tree hash, parent hashes, `GroupInfo` signer, and presence of the joining
KeyPackage leaf.
