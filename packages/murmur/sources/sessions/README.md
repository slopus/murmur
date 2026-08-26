# Sessions

`MurmurClient` is the stateful public facade. It owns account restoration,
device self-registration, bare KeyPackage creation, session lifecycle, service
routing, durable synchronization, and cleanup.

```text
bare KeyPackage -> sealed Welcome -> pending session -> activate or ignore
active epoch -> persisted ratchet + exact outbox -> relay echo -> convergence
```

Incoming protocol work advances even while a session is pending. Application
updates remain bounded and hidden until activation. The identity-wide update
batch drains only after every required service and application callback
resolves.

The implementation persists session records, active and staged epochs, intents,
outboxes, replay markers, routing decisions, and queue progress atomically.
