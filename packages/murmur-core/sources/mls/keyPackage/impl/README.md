# Key-package implementation

TLS/MLS binary encoding for the deliberately narrow KeyPackage profile. Unknown
extensions and capability variants are rejected until their behavior is
implemented.

```text
KeyPackage
  +-- init HPKE public key
  +-- signed key-package-source LeafNode
  +-- narrow capabilities/extensions
  `-- outer KeyPackage signature
          |
      strict TLS/MLS bytes
```

Decoding validates the supported profile before any private bundle is selected
for an Add.
