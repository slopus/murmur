# HTTP tests

End-to-end Fetch coverage for publish, authenticated read, acknowledgement,
bounded bodies and responses, exact CORS reflection, oversized-delivery skip
metadata, mandatory admission context, and per-address admission bounds.

```text
protocol JSON -> Fetch handler -> real RelayService -> in-memory SQLite
```
