# LeafNode tests

Wire-order, source-context, capability, extension, and signature-field codec
coverage.

```text
key-package leaf -> exact field order -> round trip
update/commit leaf + wrong context ----> signature mismatch
GREASE values -------------------------> retained
forbidden default capabilities --------> rejected
```

The tests pin the bytes used by KeyPackage references and ratchet-tree hashes.
