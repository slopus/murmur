# Session implementation tests

Focused unit coverage for strict session frame codecs, durable records, and
engine mechanics that do not require the public synchronization integration.

```text
untrusted frame bytes -> strict parser -> normalized internal frame
```

Session control vectors contain role state only.
