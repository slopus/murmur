# Protocol

Relay, discovery, delivery, and MLS session formats are version `1`. The
built-in contact protocol and its persisted records are version `2`.

## Identity and discovery

One 32-byte identity root derives one Ed25519 public identity and the X25519
material used by sealed bootstrap delivery. Internally, keys remain
`Uint8Array`; base64url is used only at serialization boundaries.

`MurmurClient.createInvitation()` creates:

- one signed, self-contained bundle with a five-minute expiry;
- one current public MLS KeyPackage in that bundle;
- the matching one-use private KeyPackage state in the local store.

The client uploads the exact bundle bytes to the relay's non-enumerable
five-minute cache and receives their 32-byte SHA-256 digest. The application
shares only that digest. `resolveInvitation()` fetches the bytes and verifies
the digest, signed expiry, identity signature, and KeyPackage signatures. The
relay is not a directory and cannot resolve or enumerate identities.

Revocable cache registration uses a second durable Ed25519 root generated for
the Murmur store. The invitation identity signs a domain-separated canonical
authorization binding its exact digest and expiry to that revocation public
key. The private revocation root is never included in the discovery bundle or
returned to recipients. `revokeInvitation()` signs one digest;
`revokeInvitations()` signs `digest: null` for every unexpired row registered to
that authority. Relay replacement of a live row with an expiring tombstone is
atomic and prevents re-upload of the same public bytes until their original
expiry.

Before sending a revocation request, the client durably marks the affected
invitation records and destroys their unused private KeyPackages. Failed relay
requests remain pending across restart and are safe to retry. Until a retry
reaches the relay, a cached public bundle can still resolve even though its
Welcome can no longer consume local private state. Revocation never removes an
already established MLS session.

The prospective member deletes matching private KeyPackage state when its
Welcome is consumed, or on the next client operation after the five-minute
invitation expires and before any later Welcome can be processed. A creator's
durable one-use claim remains until the KeyPackage's `notAfter` boundary so the
same public KeyPackage cannot be rewrapped and reused.

## Bootstrap

Creating or adding a member prepares one MLS Commit plus one sealed Welcome for
each addition. The Commit outbox contains the complete expected Welcome ID
manifest. Before publishing any Welcome, Murmur validates the Commit, local
staged state, every child record, and every secondary index.

Successful Welcome publications leave durable markers. The Commit publishes
only after all markers are present and all older current-epoch application
outboxes have settled. The sender adopts the Commit only from its own identity
queue echo; a publish response never advances the epoch.

A pending session may replace its bootstrap only with a newer relay event whose
Commit extends at least the pending session's base epoch and names the same
owner. This permits a fresh Welcome after a losing Add race while rejecting a
later-delivered sibling Welcome from another Commit against the old epoch.

A valid received Welcome creates a bounded `pending` session. MLS protocol
traffic continues while pending. A built-in contact descriptor keeps its
profile hello internal until explicit acceptance or rejection. Other
descriptors are offered to registered services; the first `onNewSession`
returning `true` becomes the durable owner, while a fully declined session is
consumed. Manually managed sessions remain pending until `activateSession`.

Service sessions normally name confirmed contact identities rather than public
discovery bundles. Murmur consumes one cached admission KeyPackage from every
contact and creates the complete group without requiring those contacts to be
online.

## Realtime queue stream

`POST /v1/queue/events` authenticates with the same domain-separated signed
queue-read object as a bounded read, with `waitMilliseconds: 0`. A successful
response requires `limit: 1` for one-event storage backpressure and is
`text/event-stream`. Each delivery record is:

```text
id: <lowercase UUIDv7>
event: delivery
data: {"eventId":"<same UUIDv7>","delivery":<SignedDeliveryJson>}

```

The relay emits records in that recipient inbox's UUIDv7 order and sends
comment heartbeats without advancing progress. It may buffer, disconnect,
repeat, delay, or omit events; SSE receipt is never acknowledgement. Murmur
processes one record through the ordinary durable queue transaction, sends a
signed acknowledgement, and reconnects from its durable cursor.

Every active-session application event is also indexed locally by that relay
UUIDv7 ID. One `sync({ onUpdates })` loop reads a bounded cross-session batch in
inbox order. Registered `onUpdate` handlers and contact lifecycle hooks run
inside the same cycle; global `onUpdates` sees service-owned updates with their
stable service ID. Murmur atomically removes the complete batch only after
every relevant callback resolves. No Murmur storage transaction is exposed.

## Contacts and service packets

The built-in contact descriptor is canonical
`{"protocol":"murmur.contacts","version":2}`. Its two-person MLS session carries
canonical `hello`, `admission_request`, `admission_response`, and `remove`
packets, plus a canonical `profile_update` carrying a positive monotonic
revision and bounded replacement profile. Each hello includes a bounded
application profile, fifteen identity-bound one-use MLS KeyPackages, and one
long-lived reusable last-resort KeyPackage. A contact is confirmed after both
authenticated profile/admission hellos are processed.

`updateContactProfile()` commits the identity-wide local profile revision,
every active contact's mirrored local profile, and all corresponding technical
session outboxes in one store transaction. Recipients authenticate the MLS
sender, accept only a greater remote revision, and durably emit one
`onContactUpdated` lifecycle event. Equal identical revisions and lower
revisions are no-ops; equal conflicting revisions are rejected. Removing and
removed contacts are excluded.

Creating or extending a service group consumes one remote one-use package. At
the low watermark Murmur durably queues a refill request through the contact
session. If the contact is offline and the pool empties, the last-resort
KeyPackage may bootstrap multiple independent groups; its matching private
bundle is deliberately retained after each Welcome. Every last-resort use also
requests a refill. A response replaces the remote inventory and rotates the
fallback. This prioritizes offline availability while ordinary operation keeps
the stronger deletion-after-one-Welcome property.

Optional services use application-defined typed packets inside ordinary MLS
application bytes. A stable service ID owns each claimed session durably.
Service persistence is canonical JSON over the same ordered Murmur key/value
store under a restricted versioned namespace.

## MLS sessions

Two-member and many-member sessions use the same RFC 9420 profile:

- X25519, HKDF-SHA-256, AES-128-GCM, and Ed25519;
- BasicCredential bound to the Murmur identity key;
- TreeKEM Adds, Removes, Welcome, Commit, and PrivateMessage;
- one MLS-authenticated role state containing an immutable owner, admins, and
  membership policies.

Membership and role API calls persist bounded local intents. Any current member
may publish a Commit that the prior epoch's role state authorizes. The owner is
always an admin and cannot be removed or demoted. Admins remove other accounts;
non-owner accounts may leave; adding requires an admin unless the
`anyoneCanAddMembers` policy is enabled. Only the owner revokes admins or
changes policies, while `adminsAssignAdmins` permits admins to grant admin.

An atomic Commit multicast receives one UUIDv7 event ID shared by every current
member inbox. Each recipient accepts the first valid Commit for its current
epoch and treats later siblings as stale. A member whose staged Commit loses
re-encrypts dependent sends against the winning epoch and retries its durable
intent. Add intents snapshot a per-account removal generation, preventing a
stale intent from silently re-admitting a recently removed account.

Application sends clone and persist the post-ratchet epoch plus exact outbox
before publication. Commit preparation persists active and staged epochs
separately. Remove drops prior-epoch receive state immediately; other membership
changes retain a small time- and message-bounded prior-epoch window for in-flight
traffic.

## Delivery and replay

Every sender-signed delivery carries:

- a stable sender-scoped delivery ID;
- sorted unique recipient identities;
- creation and expiration times;
- opaque ciphertext;
- an Ed25519 signature over a domain-separated canonical encoding.

The relay may forget a delivery ID after all references disappear. Recipients
therefore persist sender-plus-delivery-ID replay state. Exact records are
bounded; capacity overflow enters a bounded probabilistic filter whose only
error is rejecting a new delivery. A separate rotating terminal filter
amortizes repeated invalid-input authentication work without accumulating
forever. Replay state and cursor progress commit with the buffered application
update or terminal rejection.

Relay UUIDv7 event IDs provide a monotonic per-inbox cursor and processing-time
floor. Implausible event times reject the page without durable mutation.

## Queue acknowledgement

Reads and acknowledgements are signed by the recipient identity. After durable
processing, the client acknowledges through its latest cursor. Acknowledgement
is monotonic and idempotent while queue state exists. Once an inbox has no
pending references, the relay may reclaim its row; an absent inbox is an empty
state, not retained history.
