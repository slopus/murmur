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

MLS KeyPackages are signed by the device identity. `createKeyPackage()` stores
the matching one-use private bundle durably and returns bare public admission
material containing the account identity and encoded KeyPackage.

## Delivery envelope

One sender-signed delivery contains:

- a random operation ID;
- sender and exact recipient public identities;
- creation and expiry times;
- opaque ciphertext;
- an Ed25519 signature over a domain-separated canonical encoding.

The relay validates size, time, identity, recipient, and signature policy before
an atomic multicast. One accepted operation receives one UUIDv7 event ID and
one monotonically increasing sequence in every recipient inbox. Duplicate
pending publication returns the original event ID.

Reads and acknowledgements are independently signed by the recipient. An inbox
page includes its head, head sequence, acknowledged prefix, continuity
generation, exact ordered deliveries, and exhaustion flag. Acknowledgement is
monotonic and destructively trims the processed prefix.

## MLS bootstrap

Session creation consumes bare admission material for every new member. Murmur
creates the initial MLS epoch, a Welcome for each recipient, and exact durable
outboxes. A recipient authenticates and decrypts the Welcome using the retained
one-use private KeyPackage bundle.

The resulting session starts pending. Protocol frames continue to advance the
pending epoch, while application frames remain buffered and hidden. The
application activates or ignores the pending session locally.

## Session traffic

Application messages use MLS private-message ratchets. Every membership or role
change is an MLS Commit. One authenticated epoch committer serializes Commits;
other members submit proposals. A staged send waits for its owning Commit and
all required Welcomes before publication.

Authenticated session control carries the immutable owner, admin set, and two
policies:

- whether admins may grant admin to another member;
- whether every member may add another member.

The owner is always an admin. Removal immediately revokes prior-epoch send
authority for the removed account.

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

## Continuity loss

Every inbox has a random continuity generation and contiguous sequence. A
generation change or sequence rollback records a bounded reset event containing
the final local session snapshot. After the application resolves `onReset`,
Murmur purges technical state, adopts the new inbox baseline, and retains
readmission descriptors needed for convergence.
