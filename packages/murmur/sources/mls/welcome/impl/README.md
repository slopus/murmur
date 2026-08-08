# Welcome internals

Strict RFC 9420 codecs for `Welcome`, `EncryptedGroupSecrets`, and an
extension-free `GroupInfo`.

```text
Welcome
  +-- cipher suite
  +-- KeyPackageRef -> HPKE EncryptedGroupSecrets
  `-- encrypted GroupInfo
        +-- GroupContext/tree hash
        +-- confirmation tag
        `-- signer + signature
```

The parent join flow authenticates these decoded structures against the
externally supplied ratchet tree.
