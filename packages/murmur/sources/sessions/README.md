# Sessions

`MurmurClient` is the stateful public facade. It owns account restoration,
device self-registration, direct and directory KeyPackage admission, session
lifecycle, service routing, durable synchronization, and cleanup.

```text
bare KeyPackage -> sealed Welcome -> pending session -> activate or ignore
ticket + exact account -> per-device claim -> sealed Welcomes
active epoch -> persisted ratchet + exact outbox -> relay echo -> convergence
```

Incoming protocol work advances even while a session is pending. Application
updates remain bounded and hidden until activation. The identity-wide update
batch drains only after every required service and application callback
resolves.

The implementation persists session records, active and staged epochs, intents,
outboxes, replay markers, routing decisions, and queue progress atomically.

Creation selects an `everyone` or `admins` send policy. Policy changes are
owner-only and Commit-bound; local sends and exact-epoch remote senders are
checked before application data is accepted. Owner deletion durably separates
the account-signed relay purge request and final MLS notice from session state,
so local cleanup is terminal while publication remains retryable.

`deleteAccount()` first persists and submits one account-signed terminal relay
request. After confirmation, or a replay proving earlier acceptance, one store
transaction removes every local key and the client destroys both identity roots
in memory. It does not erase authenticated MLS events already held by remote
members; those sessions converge later through silence or explicit removal.

`claimAccount()` validates every returned MLS signature, lifetime, device key,
and account credential before exposing an immutable claim. `createSession()`
and `addMember()` flatten that claim into device-level MLS additions. Client
open publishes initial directory material, ordinary spent notices trigger
replenishment, and `rotate()` replaces the local directory generation.
