# Protocol

## Identity

A local device has one Ed25519 public identity key. Its signing key and X25519
agreement key derive from one 32-byte root. Secret keys are byte arrays in
memory and base64url appears only at wire or storage boundaries.

The optional local account-secret envelope combines a generated 256-bit string
and user password through HKDF-SHA-256 and scrypt, then protects the root with
AES-256-GCM. Its versioned canonical binary blob is application-owned and has no
relay operation or recovery endpoint. Password rewrapping preserves the full
typed root-material payload while rotating the salt and nonce.

MLS KeyPackages are signed by the device identity and bind the stable account
identity in their credential. `createKeyPackage()` stores one matching private
bundle for direct application-routed admission. Directory admission instead
maintains a pool of one-use KeyPackages and exactly one reusable last-resort
KeyPackage for every active account device.

## Identity directory

Opening an HTTP-backed client automatically uploads each device's initial
directory pool. The upload is an account-signed, recipientless delivery bound
to the current device roster generation. `rotate()` replaces all unclaimed
one-use packages and the last-resort package; automatic replenishment appends
fresh one-use packages while naming the unchanged last-resort reference.
Upload operation IDs and retired directory references are replay-protected
permanently. After an ambiguous transport response, byte-identical active
one-use entries and the exact current last-resort entry may be reasserted
idempotently; they cannot be changed under an existing reference.

An authentication server issues opaque, signed tickets with an expiry and an
exact-claim budget. The relay verifies a ticket through a pluggable verifier and
atomically spends one budget use when claiming an exact 32-byte account key.
Each active device contributes its oldest unexpired one-use KeyPackage, or its
nonconsuming last-resort package when the pool is empty. Unknown accounts return
the same response envelope with revision zero and no devices; there is no
listing, search, prefix, or existence endpoint.

Consuming a one-use package atomically queues its device-signed spent notice to
the owning device's ordinary inbox. Murmur retains the matching private bundle
until it accepts the corresponding Welcome, or until explicit rotation removes
it, and automatically replenishes spent pool slots. A last-resort private
bundle remains reusable until rotation, so independent Welcomes produced from
the same fallback package are valid.

## Delivery envelope

One sender-signed delivery contains:

- a random operation ID;
- sender and owning sender account;
- either exact recipient public identities for direct inbox delivery or no
  recipients for session-addressed delivery;
- nullable owner-account and session identifiers for relay-side terminal cleanup;
- nullable relay-visible session control covering epoch, device coverage, and,
  for creation and Commits, post-Commit membership and roles;
- creation and expiry times;
- opaque ciphertext;
- an Ed25519 signature over a domain-separated canonical encoding.

The relay validates size, time, identity, routing, and signature policy before
an atomic multicast. For ongoing MLS traffic it authenticates a current member
device, advances relay-visible creation or Commit state in delivery order,
enforces basic roles and send policy, joins member accounts to current rosters,
and derives the exact device fanout. One accepted operation receives one UUIDv7
event ID and one monotonically increasing sequence in every derived or direct
recipient inbox. Duplicate pending publication returns the original event ID.

Reads and acknowledgements are independently signed by the recipient. An inbox
page includes its head, head sequence, acknowledged prefix, continuity
generation, exact ordered deliveries, and exhaustion flag. Acknowledgement is
monotonic and destructively trims the processed prefix.

## MLS bootstrap

Session creation consumes either bare admission material or an exact-account
directory claim. A claim expands to one current admission per account device.
Murmur creates the initial MLS epoch, a Welcome for each recipient, and exact
durable outboxes. A recipient authenticates and decrypts the Welcome using its
retained one-use or reusable last-resort private KeyPackage bundle.

The resulting session starts pending. Protocol frames continue to advance the
pending epoch, while application frames remain buffered and hidden. The
application activates or ignores the pending session locally.

## Session traffic

Application messages use MLS private-message ratchets. Every membership or role
change is an MLS Commit. One authenticated epoch committer serializes Commits;
other members submit proposals. A staged send waits for its owning Commit and
all required Welcomes before publication.

Authenticated session control carries the immutable owner, admin set, and
three policies:

- whether admins may grant admin to another member;
- whether every member may add another member;
- whether everyone or only admins may send application events.

The owner is always an admin. Removal immediately revokes prior-epoch send
authority for the removed account.

Every ongoing send names only the session and declares the devices covered by
its MLS epoch. If a current roster contains an uncovered device, the relay
returns `stale_epoch_coverage` with current rosters; the client adds the leaf
and re-encrypts. Members independently compare signed visible controls with the
decrypted MLS message or Commit and durably quarantine any mismatch. A bounded
prior-epoch message racing a winning Commit remains decryptable by members that
held that epoch, while the relay rejects removed senders.

The immutable owner may delete an idle active session. Murmur first durably
creates an account-signed, replay-protected relay purge request and a final
direct-inbox MLS deletion notice, then destroys local session state. The relay removes every
unexpired delivery carrying that exact owner/session pair and advances affected
inbox continuity generations before Murmur publishes the final notice. Members
authenticate the notice against the owner role in its exact MLS epoch and
terminally destroy their local state. A service-owned session receives one
durable typed deletion event; a thrown callback retries that same event ID.

## Durable application boundary

Murmur prepares one identity-wide ordered update batch. Registered services
process claimed updates first. The global `onUpdates` hook then receives all
remaining opaque application updates. The whole batch drains only after every
required hook resolves.

Queue progress, replay markers, buffered events, lifecycle records, and routing
decisions commit together. A thrown hook therefore retries the same durable
effect without reapplying protocol state.

## Account devices

Restoring an account identity on a new store generates an independent device
inbox key and account-signs a self-registration mutation containing its reset
generation and current MLS KeyPackage. The relay replay-protects the mutation,
atomically updates its one current roster, and queues that same ordinary
delivery to every post-mutation device inbox. Account-signed removal may name
the current device or any sibling.

Account-targeted deliveries sign each account key and source roster revision.
The relay rejects stale revisions or omitted current devices and returns the
current roster. The client durably observes it, retargets the exact outbox, and
drives ordinary MLS Add or Remove convergence. Pure inbox publication has no
roster target and is unchanged.

Every ordinary device publication signs its owning account. The relay accepts
that ownership only when the sender is an active device in the current roster;
account-signed control traffic names the account itself. This binding lets the
relay remove every pending outbound delivery owned by an account without
interpreting ciphertext.

## Account deletion

`deleteAccount()` durably submits one account-identity-signed, replay-protected
terminal request. The relay handles an authenticated missing account as the
same successful no-op as an existing account. SQLite and PostgreSQL atomically
remove the account roster, dependent directory state, every device inbox and
continuity row, raw account nonces, and all pending outbound deliveries owned by
the account. Cloudflare first commits removal of authoritative roster,
directory, and session control state, then durably retries deletion of each
known device inbox through alarms; its success response can precede completion
of that cross-object physical purge. A hashed request tombstone remains for the
delivery-retention window.

Only after relay confirmation does the client remove every local store key and
destroy its device and account roots in memory. This operation does not erase
MLS events already authenticated and stored by remote members. Their sessions
remain until silence or an authorized member removal makes them converge.

## Continuity loss

Every inbox has a random continuity generation and contiguous sequence. A
generation change or sequence rollback records a bounded reset event containing
the final local session snapshot. After the application resolves `onReset`,
Murmur purges technical state, adopts the new inbox baseline, and retains
readmission descriptors needed for convergence.
