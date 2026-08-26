# Services

Optional typed synchronization capabilities registered on one Murmur client.
Account synchronization remains internal and is not a service.

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
          `---------------> service.onSessionDeleted(event)
```

Each registration uses an explicit stable ID. Murmur never derives persistence
identity from a JavaScript constructor or class name. `onNewSession` claims a
session, `onUpdate` consumes later updates routed to that owner, and the
optional `onSessionDeleted` receives its final typed owner-deletion event.

Plugin hosts may use the package-root `validateServiceId` and
`validateMurmurServiceRegistration` helpers before registering dynamic service
configuration. The defensive descriptor factory itself remains internal;
applications receive `MurmurServiceSessionDescriptor` values through
`onNewSession` rather than constructing Murmur's callback boundary.

Claimed updates also appear in the identity-wide global `onUpdates` batch with
the stable service ID. Murmur drains the batch only after the service handlers
and global hook resolve.

Deletion state is already terminal when `onSessionDeleted` runs. Throwing
retains the same durable event ID and retries the callback without restoring or
reprocessing the deleted session.

Murmur persists only the session-to-service owner mapping. Custom services own
any application state through persistence they choose; Murmur does not provide
service storage or expose `MurmurStore` to them.
