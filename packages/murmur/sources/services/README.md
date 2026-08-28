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
the stable service ID. Murmur durably receipts each completed service callback
before invoking the global hook, so a global-hook failure does not deliberately
repeat the service callback. A crash between an external callback and its
receipt can still repeat the stable update ID.

Deletion state is already terminal when `onSessionDeleted` runs. Throwing
retains the same durable event ID and retries the callback without restoring or
reprocessing the deleted session.

The identity-wide synchronization options also expose `onSessionsChanged`.
It receives complete confirmed snapshots for application- and service-owned
sessions after activation and every adopted membership, device, role, or policy
Commit, including one final `removed` snapshot when the local account leaves.
The optional `service` field identifies claimed sessions. Throwing retains the
same stable relay event IDs across retries and restarts. When the optional hook
is absent, Murmur drains the snapshots instead of retaining unused lifecycle
history.

Every pending route, application update, and lifecycle snapshot is
durably indexed by its authenticated relay event ID. Murmur drains only the
global head: it commits one route before re-preparing, settles one lifecycle
snapshot before re-preparing, or settles one contiguous update segment ending at
the next route or lifecycle boundary. An unresolved route or failed callback
therefore blocks all later relay-derived effects across every session.

Lifecycle snapshots never coalesce. A delayed service claim preserves and then
delivers the bootstrap-time snapshot, every pending update, and every pending
Commit snapshot in relay order. The shared effect queue is hard-bounded at 1,000
records; an inbox event that would add effects beyond that limit is deferred with
its complete inbox transaction rolled back, then retried after the queue drains.
Terminal destruction purges stale snapshots, while corruption recovery drops and
reports only malformed records or indexes. A local-account removal preserves
earlier updates and snapshots ahead of its final `removed` snapshot. The
identity-wide `onIssues` hook exposes Murmur's existing bounded durable issues
when that set changes, for terminal operation handling without adding another
service method; malformed issue records are dropped.

Stable service IDs may use dots and hyphens between lowercase alphanumeric
segments; `crdt.loro` is valid.

Incoming routes are offered in lexical service-ID order, regardless of
registration order, and the first claim wins. With no registered services an
unresolved route remains durable and blocks the identity-wide effect queue. If
at least one service is registered and every service declines, Murmur
permanently ignores the session. Unregistering a durable owner does not transfer
ownership: updates and deletion notifications for the absent service are
consumed, so applications must keep owners registered until their sessions end.

Murmur persists only the session-to-service owner mapping. Custom services own
any application state through persistence they choose; Murmur does not provide
service storage or expose `MurmurStore` to them.
