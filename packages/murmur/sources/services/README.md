# Services

Optional typed synchronization capabilities registered on one Murmur client.
Contacts remain built in and are not a service.

```text
new MLS session descriptor
          |
          v
service.onNewSession() -- false --> next service / ignored
          |
         true
          v
durable session owner ------> service.onUpdate(update)
          |
          +------ scoped canonical-JSON state
```

Each registration uses an explicit stable ID. Murmur never derives persistence
identity from a JavaScript constructor or class name. A service has exactly two
protocol entry points: `onNewSession` claims a session and `onUpdate` consumes
later updates routed to that owner.

Claimed updates also appear in the identity-wide global `onUpdates` batch with
the stable service ID. Murmur drains the batch only after the service handlers
and global hook resolve.

`createMurmurServiceStorage` restricts persistence to versioned
`murmur/services/v1/<encoded-service-id>/state/` keys. It exposes only canonical
JSON and never the underlying Murmur transaction.
