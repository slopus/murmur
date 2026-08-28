# Sessions

`MurmurClient` is the stateful public facade. It owns account restoration,
device self-registration, direct and directory KeyPackage admission, session
lifecycle, service routing, durable synchronization, and cleanup.

```text
bare KeyPackage -> sealed Welcome -> pending session -> activate or ignore
ticket + exact account -> per-device claim -> sealed Welcomes
active epoch -> persisted ratchet + session-addressed outbox -> relay echo -> convergence
```

Incoming protocol work advances even while a session is pending. Application
updates remain bounded and hidden until activation. The identity-wide update
batch drains only after every required service and application callback
resolves.

The implementation persists session records, active and staged epochs, intents,
outboxes, replay markers, routing decisions, and queue progress atomically.
For service-owned sessions it also persists complete confirmed lifecycle
snapshots with the bootstrap or Commit that produced them. The identity-wide
callback settles those records only after it resolves, and a removed local
account receives its final snapshot before the session is destroyed.

Creation selects an `everyone` or `admins` send policy. Policy changes are
owner-only and Commit-bound; local sends and exact-epoch remote senders are
checked before application data is accepted. Signed visible controls summarize
each creation, Commit, and ongoing message. A mismatch with decrypted MLS state
is durably quarantined. A newly added device keeps the bounded signed membership
control until its direct Welcome arrives, then compares the epoch, owner, roles,
member accounts, and covered devices before persisting the joined epoch. The
relay derives current-device fanout; stale epoch coverage drives a device-add
Commit and re-encryption without reconstructing a recipient list on ordinary
sends.

Owner deletion durably separates the account-signed relay purge request and
final direct MLS notice from session state, so local cleanup is terminal while
publication remains retryable.

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
