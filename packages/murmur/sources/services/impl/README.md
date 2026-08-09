# Service internals

Mechanical validation and routing persistence used by the optional service
layer.

```text
service id -> strict stable identifier
session id -> session owner
event UUID -> routed-session marker
```

`serviceId.ts` validates stable IDs. `serviceRecords.ts` owns strict versioned
codecs for Murmur's durable routing. Decoders reject unknown fields and
non-canonical JSON. Custom-service application state is outside this module.
