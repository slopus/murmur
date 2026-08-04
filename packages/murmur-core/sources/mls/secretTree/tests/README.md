# Secret tree tests

Coverage for sender agreement, out-of-order delivery, replay rejection,
handshake/application separation, forward limits, and secret destruction.

```text
sender g0,g1,g2 -> receiver opens g2 -> cache g0,g1 -> open out of order
reopen consumed g1 --------------------------------> replay rejection
handshake g1 != application g1 --------------------> domain separation
far-future generation -----------------------------> bounded rejection
```

Snapshot tests additionally prove the restored frontier cannot regenerate
already-erased ancestors.
