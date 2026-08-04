# Storage tests

Contract tests for transaction serialization, rollback, copying, and prefix
enumeration.

```text
write copy -> mutate caller bytes -> stored bytes unchanged
transaction -> injected throw ----> snapshot restored
scan page --> after + limit -------> ordered bounded keys
concurrent write ------------------> serialized after rollback
```

The memory store is the executable reference for the application-provided
`MurmurStore` contract.
