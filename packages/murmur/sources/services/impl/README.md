# Service internals

Mechanical persistence used by the optional service layer.

```text
service id -> encoded namespace -> canonical JSON values
session id -> session owner
event UUID -> routed-session marker
```

`serviceStorage.ts` validates stable IDs, relative keys, JSON bounds, and scan
bounds. `serviceRecords.ts` owns strict versioned codecs for durable routing.
Decoders reject unknown fields and non-canonical JSON.
