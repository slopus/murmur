# Storage

The `RelayStore` contract is the only persistence dependency of relay policy.
Both backends expose identical atomic behavior:

```text
topic lock / BEGIN IMMEDIATE
        |
permanent receipt -> conflicts -> seq allocation -> state + retained event -> commit
```

`sqlite` is a synchronous single-process WAL implementation. `postgres` uses
per-topic advisory transaction locks and explicit versioned migrations. The
shared `impl` planner keeps list and snapshot conflict semantics identical.
Relay policy passes list capacity explicitly into every atomic `publish`, and
the receipt lookup is part of the store contract, so a custom store cannot omit
either concern accidentally. Page reads also receive an encoded-byte constraint;
both SQL backends filter by cumulative size before returning rows, and the HTTP
encoder applies the exact final response bound.
