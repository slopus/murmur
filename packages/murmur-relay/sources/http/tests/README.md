# HTTP tests

End-to-end Fetch coverage for publish, authenticated read, acknowledgement,
bounded bodies and responses, exact CORS reflection, oversized-delivery skip
metadata, mandatory admission context, and per-address admission bounds.

Directory coverage verifies valid, expired, forged, and budget-exhausted
tickets, identical known/unknown response envelopes, and the deliberate
directory exemption from generic address admission.

Every route uses the real queue service and current exact request shapes.

```text
protocol JSON -> Fetch handler -> real RelayService -> in-memory SQLite
```
