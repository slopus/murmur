# Welcome tests

Coverage for KeyPackage-targeted HPKE delivery, GroupInfo confirmation and
signature authentication, epoch agreement, init-key consumption, and failure
rollback.

```text
create Welcome(A->B) -> B opens -> context/epoch secrets agree
wrong tree/signer/tag ---------> reject
successful join ---------------> zero init private key
failed join -------------------> preserve bundle for retry
```

The tests distinguish cryptographic consumption after success from recoverable
validation failure.
