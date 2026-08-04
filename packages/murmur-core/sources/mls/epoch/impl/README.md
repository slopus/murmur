# Epoch implementation

Internal codecs for durable local MLS epoch state. Persisted state contains
epoch and ratchet secrets, so callers must store the encoded bytes with the
same confidentiality and filesystem protections as identity private keys.

```text
MlsEpochState
  +-- authenticated public tree
  +-- local TreeKEM private path
  +-- Secret Tree frontier/generations
  `-- epoch secrets + persistenceGeneration
             |
          strict sensitive checkpoint
```

The codec excludes the identity signing secret, which must be supplied and
revalidated when the checkpoint is restored.
