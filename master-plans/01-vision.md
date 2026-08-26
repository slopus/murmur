# Murmur as a focused stateful MLS library

## Vision

Murmur is a stateful library for discovering a public account identity,
bootstrapping an MLS session, and exchanging data through typed
synchronization services. A two-person interaction and a many-person
interaction use the same MLS group primitive. There is no built-in contact
protocol: sharing a public identity key is enough to claim published
KeyPackages through the identity directory and instantly start a session or
group. Chat remains an optional independent
service, and the old friend-channel and generic relay-topic machinery are not
part of Murmur.

It ships as the browser-safe and Node.js-compatible `@slopus/murmur` library.
The relay is internal infrastructure. Chat, documents, and other application
protocols live in optional typed services rather than in the relay or the MLS
engine.

The pre-v0.3 rewrite remains a clean break: its APIs, codecs, relay topics,
storage schemas, and CLI are unsupported. Version 0.3.3 is the compatibility
baseline. From that release onward, public library APIs and wire formats remain
backward-compatible, persisted client state remains readable or is migrated,
and relay schemas migrate in place without deleting pending data or requiring a
clean database.

## Relay transports and device identities

The existing relay protocol remains supported unchanged: one public device
identity has one authenticated inbound queue, bounded HTTP reads, and one
signed SSE receiver. Applications may continue configuring that relay directly.

An additive negotiated protocol supports independent devices. A main server
authenticates an application user, verifies that the user controls one Murmur
account device, and issues a short-lived token naming the assigned endpoint
and transport protocol. The endpoint may be the main server or a stateful edge
object reached through its public ingress. The first negotiated transport uses
an authenticated WebSocket.

One application user has one stable Murmur account identity and may authorize
multiple independently keyed devices through its signed device roster. Every
device has its own device key, MLS leaf and ratchets, durable Murmur store, and
authenticated inbox; devices never share sender or epoch state. Active devices
synchronize Murmur-owned account state and automatically drive their MLS
membership across known account sessions. The server may retain the bounded
account-to-device routing needed to issue tokens and deliver traffic, but it
cannot forge the roster and receives no device secrets.

The relay stores encrypted deliveries that remain unacknowledged and unexpired.
It is an identity directory: it holds each published account's per-device pool
of one-use KeyPackages and its multi-use last-resort KeyPackage, resolvable
only by the exact public identity key and gated by contact tickets from the
authentication server, as dictated by the identity-directory plan. It may also
hold a signed discovery bundle for at most five minutes under the SHA-256
digest of its exact bytes. It stores no snapshots, retained chat
history, event-sourced application state, anonymous capability topics, or MLS
state.

User admission, device, endpoint, sender, recipient, timing, queue, and fanout
metadata are an accepted tradeoff. Murmur promises encrypted contents, not
anonymous routing.

## Ownership of state

The application supplies transactional persistence for Murmur and owns
application history and effects, but Murmur never exposes its storage
transaction to application code. Murmur owns identity secrets, current MLS
epoch and ratchet checkpoints, KeyPackages, Welcomes, outboxes, replay and queue
progress, pending-session buffers, session lifecycle, and synchronization. For
realtime receiving, the configured transport streams the exact queued
encrypted deliveries over the device's authenticated SSE or WebSocket
connection in inbox UUIDv7 order.

Every local session operation works offline and completes against durable local
state before Murmur lazily shares its outboxes with the relay. Relay
connectivity, peer presence, session creation, pending local activation, and a
staged membership Commit never make `send` wait or reject. A send made while a
Commit is staged encrypts immediately with the staged post-Commit epoch,
durably advances that staged ratchet, and is ordered after its prerequisite
Welcome and Commit. The sender still adopts the Commit as its active epoch only
from its authenticated queue echo; adoption is not permission to send.

A relay item is acknowledged only after its queue-processing outcome is
durable. Successful session processing atomically persists Murmur state, replay
and queue progress, and a bounded opaque application update before
acknowledgement. One identity-wide synchronization loop routes an inbox-ordered
batch to registered session owners and the relevant main sync callbacks. The
main sync options include `onUpdates`, but `onUpdates` is never a fallback for
an unclaimed session. Only after all relevant asynchronous handling resolves does Murmur
atomically drain the whole local batch. A thrown handler or crash before that
internal commit exposes the same stable event IDs again; applications needing
durable exactly-once effects deduplicate those IDs in their own persistence.

A valid bootstrap becomes a durable pending local bootstrap or session together
with replay and queue progress before acknowledgement; the application later
activates or ignores it locally. While pending, Murmur continues advancing its
MLS state and durably buffers opaque application events without exposing them,
so later queue items can also be acknowledged without waiting. Pending state
and buffered data are strictly bounded. Activation makes its buffered events
visible to the appropriate owner in the same identity-wide loop; ignore or
overflow terminally rejects the session and destroys pending secrets and data
while retaining replay and rejection state.

Malformed, unauthenticatable, undecryptable, unsupported, ignored during queue
processing, or otherwise terminal deliveries are durably rejected or
quarantined with replay and queue progress and no application effect before
acknowledgement. A crash before acknowledgement causes expected redelivery.

Relay replay is not a recovery mechanism. Losing the local store or device
loses its protocol state and application history; account-identity continuity
does not reconstruct them. Recovery requires a backup or authorization as a
fresh device followed by new MLS Welcomes.

## The layers, in order

1. **Account and devices.** Create a stable account identity, authorize
   independently keyed devices through a signed roster, synchronize those
   devices, and converge their membership across known MLS sessions.
2. **Admission and routing.** Continue supporting a directly configured legacy
   relay, or ask the application authentication server for a short-lived token
   that binds one authorized account device to an endpoint and transport.
3. **Discovery.** Publish each account's per-device one-use KeyPackage pool
   and multi-use last-resort KeyPackage to the relay's identity directory,
   resolvable only by the exact public identity key and claimed with a contact
   ticket. An application may also share a self-contained signed bundle
   directly, or upload it to the relay's five-minute content-addressed cache
   and share only its SHA-256 digest.
4. **Bootstrap.** Create an MLS session and deliver its Welcome and initial
   material to the recipient's authenticated queue. The recipient persists it
   as pending and trims the queue before application acceptance.
5. **MLS sessions.** Send opaque descriptors, application events, and
   membership changes through the same MLS primitive for two or more members.
6. **Synchronization services.** Register optional independent typed services
   on the client. Each service may claim a new session from its descriptor and
   then owns later updates routed through that durable association.
7. **Private group state.** Store canonical encrypted group records behind
   anonymous, zero-knowledge membership authorization without exposing a
   readable social graph or replacing MLS membership.
8. **Applications.** Register typed synchronization services for domains such
   as chat, documents, or files.

## How we know it is done

- `@slopus/murmur` opens with a directly configured legacy relay or a negotiated
  short-lived device token and application-supplied transactional persistence
  in a browser or Node.js process without exposing storage transactions through
  its session API.
- A negotiated token binds one independently keyed account device to its
  endpoint and declares the transport protocol. The first new protocol carries
  authenticated inbox traffic over WebSocket while the HTTP/SSE protocol stays
  compatible.
- Two account devices can discover the material needed to bootstrap an MLS
  session, and the recipient can durably receive it without waiting for the
  application to activate or ignore it.
- A relay-cached discovery bundle is non-enumerable, addressed only by the
  SHA-256 digest of its exact bytes, expires within five minutes, and cannot
  extend the bundle's signed lifetime or the owner's matching private
  KeyPackage state.
- A pending session stays cryptographically current under a strict storage
  bound; activation durably hands off buffered events or effects, while ignore
  or overflow terminally rejects and destroys pending secrets and data.
- Optional strictly typed synchronization services persist their state and
  participate in the identity-wide sync loop through exactly `onNewSession`
  and `onUpdate`. A successful new-session claim durably routes later updates
  to that service.
- The same MLS session engine works for two and many members, including adding
  and removing members in service-owned sessions.
- A stable account identity has the signed roster, built-in device
  synchronization, automatic MLS convergence, revocation, recovery boundary,
  and complete tombstone defined by the multidevice plan.
- The private-group state service provides canonical encrypted group state and
  anonymous role enforcement without learning the account social graph, while
  its remaining network and delivery metadata is stated explicitly.
- Every session operation works from durable local state while offline. No
  session or synchronization state blocks `send`; sends against a staged
  membership epoch are encrypted and persisted immediately, survive restart,
  and publish only after their prerequisite Welcome and Commit.
- Queue processing survives redelivery and acknowledges only after durably
  recording queue progress and its successful protocol state plus buffered
  update, pending bootstrap, or terminal rejection.
- One `sync` loop delivers bounded identity-wide batches with stable event IDs
  to registered service callbacks and the relevant optional sync callbacks.
  Murmur commits
  and drains a whole batch only after its asynchronous handling resolves; an
  uncommitted batch is returned again after restart.
- A session that no registered service claims has its unknown updates durably
  consumed and acknowledged without a raw `onUpdates` fallback, so it cannot
  block the identity inbox.
- Realtime delivery streams exact queued events over the negotiated
  authenticated SSE or WebSocket transport in one device inbox's UUIDv7 order,
  reconnects from the durable cursor, and may redeliver but cannot replace
  durable acknowledgement.
- No legacy friend state machine, friend channel, generic topic API, CLI, or
  built-in chat-specific protocol remains.
