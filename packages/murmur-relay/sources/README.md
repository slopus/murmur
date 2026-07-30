# Sources

`relay` owns validation and fan-out. `storage` owns persistence contracts and
the reference in-memory implementation. `transport` adapts the service back to
the browser-safe core transport contract for embedding and tests.

```text
RelayTransport -> RelayService -> RelayStore
```
