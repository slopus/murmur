# Security

## Trust model

The relay is untrusted for confidentiality and session semantics. It sees public
queue identities, signed envelope metadata, timing, ciphertext sizes, recipient
fanout, ingress admission principals, and acknowledgement progress. It must not
receive MLS secrets, identity roots, plaintext descriptors, or application
updates.

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
- Zero temporary secret arrays at the end of their lifetime.
- Reject replayed KeyPackages and protocol frames durably.

Forward secrecy depends on durable epoch replacement and deletion of retired
secrets. Rollback of client storage can restore old send authority, so storage
continuity is a security property rather than an operational convenience.

## Delivery

Signed envelopes bind the operation ID, sender, exact recipient set, timestamps,
and ciphertext. The relay validates all bounds and signatures before storage.
Queue reads and acknowledgements are independently signed by the recipient.

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

Verify device-link material over an authenticated user-visible channel. Roster
revisions are signed by active account devices. Review dormant-device reports
and revoke lost devices promptly. A revoked device must be removed from every
known MLS session before it stops receiving new traffic.

## Operations

- Terminate TLS at a trusted boundary.
- Bound JSON, SSE, WebSocket, recipient, ciphertext, and response sizes.
- Monitor quota pressure, signature failures, sequence gaps, continuity changes,
  and repeated reset events.
- Exercise restore procedures and declare restored relay state before serving.
- Keep signing, token, database, and application-storage secrets in separate
  secret-management domains.
