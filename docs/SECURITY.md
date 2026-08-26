# Security

## Trust model

The relay is honest but not trusted: Murmur relies on it to apply the protocol
and delivery order correctly, but never for confidentiality or as a replacement
for member verification. It sees public queue and account identities,
relay-visible session membership and roles, signed envelope metadata, timing,
ciphertext sizes, derived fanout, ingress admission principals, and
acknowledgement progress. It must not receive MLS secrets, identity roots,
plaintext descriptors, or application updates.

The application controls its `MurmurStore` and every external effect. Compromise
or loss of that store exposes or destroys the local cryptographic state it
contains. Protect it with application-grade encryption, access control, atomic
backup, and rollback detection.

## Account secret

`createAccountSecret` combines a generated 256-bit string and the user's
password; neither input alone can derive the AES-256-GCM wrapping key. The
generated component passes through domain-separated HKDF-SHA-256, the password
component passes through scrypt with authenticated fixed cost parameters, and a
second HKDF combines them. A random salt and nonce are generated for every new
blob and every password change.

The application owns the opaque blob and generated string. Store them according
to the application's recovery policy, never log either one, and do not treat a
password change as a substitute for protecting the generated string. Murmur has
no copy, server endpoint, reset path, or recovery key. Restoring the blob yields
the identity root only; it does not restore MLS epochs, ratchets, history, or
queue progress.

## Identity and MLS

- Generate identity roots with a cryptographically secure random source.
- Keep all secret keys as byte arrays; never log or stringify them.
- Validate identity lengths, KeyPackage signatures, lifetimes, credentials, and
  key bindings before cryptographic operations.
- Destroy one-use private KeyPackage material after successful Welcome
  processing.
- Retain a claimed directory bundle until its Welcome is processed; a spent
  notice means the public package was claimed, not that the private bundle is
  already safe to destroy.
- Retain last-resort private material until explicit rotation because several
  independent Welcomes may legitimately reference the same fallback package.
- Zero temporary secret arrays at the end of their lifetime.
- Reject replayed KeyPackages and protocol frames durably.

Forward secrecy depends on durable epoch replacement and deletion of retired
secrets. Rollback of client storage can restore old send authority, so storage
continuity is a security property rather than an operational convenience.

## Delivery

Signed envelopes bind the operation ID, sender, owning sender account, direct
recipient set or relay-visible session controls, account target revisions,
timestamps, and ciphertext. The relay validates active device ownership, all
bounds, signatures, current session membership, role policy, and epoch coverage
before storage. Members still validate visible controls against decrypted MLS
state. Queue reads and acknowledgements are independently signed by the
recipient.

Use constant-time comparison for authentication values. Never log request
bodies, signatures, ciphertext, queue tokens, identity roots, or relay-session
tokens. Production ingress must authenticate callers and apply non-Sybil policy
before assigning quota principals.

## Durable effects

Murmur persists protocol progress and application batches before relay
acknowledgement. The application should apply an update batch atomically and
deduplicate by stable event ID. Throwing a callback is safe only when retrying
that same effect is safe.

Pending sessions are unsolicited cryptographic state. Keep member, byte, event,
outbox, and pending-session limits conservative. Ignore unknown descriptors and
surface only the initiator and opaque metadata needed for an informed decision.

## Multiple devices

Protect account-restoration material: possession authorizes registering and
removing devices without a sibling approval step. Review dormant-device reports
and remove lost devices promptly. The relay rejects account-targeted traffic
whose signed roster revision is stale while MLS membership converges.

Account deletion removes relay-owned and local technical state, but it is not
retroactive erasure from other members. Authenticated MLS events already held
by remote applications remain under those applications' storage policy. The
Cloudflare queue-only adapter cannot perform session-addressed publication or
terminal account deletion.

## Identity directory

Directory access reveals the exact queried identity to the relay. Tickets
authorize and rate-limit exact claims but do not make them anonymous. Ticket
issuers should authenticate callers, use short expiries and conservative claim
budgets, and avoid embedding user-readable identity data in opaque tickets.

The relay offers no listing or prefix lookup. Known and unknown exact identities
share one response envelope, and unknown claims spend ticket budget, reducing
the existence oracle to unavoidable response characteristics such as timing.
Deployments should monitor and normalize those characteristics where account
existence is especially sensitive.

Uploads are account-signed and tied to a current roster device generation.
One-use references can never be reused, rotations invalidate unclaimed private
material locally, and spent notifications are signed in advance by the owning
device so the relay cannot forge inbox control messages. The last-resort
KeyPackage deliberately trades one-use semantics for availability; rotate it
after suspected compromise or according to application policy.

## Operations

- Terminate TLS at a trusted boundary.
- Bound JSON, SSE, WebSocket, recipient, ciphertext, and response sizes.
- Monitor quota pressure, signature failures, sequence gaps, continuity changes,
  and repeated reset events.
- Exercise restore procedures and declare restored relay state before serving.
- Keep signing, token, database, and application-storage secrets in separate
  secret-management domains.
