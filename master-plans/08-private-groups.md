# Private group state

## Destination

Murmur adds a canonical private-group state service without giving that service
a readable social graph. The service stores one opaque group record containing
encrypted attributes and deterministic group-specific ciphertexts for logical
account members. It may see the opaque group identifier, revision, member
count, fixed roles attached to opaque entries, access timing, and record sizes,
but it cannot recover account identities or link the same account across
groups.

An authenticated account periodically obtains a short-lived anonymous
credential over its stable account identifier and expiry. A group member uses
a randomized zero-knowledge presentation to prove that the credential covers
the same hidden identifier as one encrypted member entry. The service can then
read or mutate the canonical record and enforce the fixed role on that opaque
entry without learning the account identity or linking credential issuance to
its group use.

After a valid presentation, the service may issue a short-lived token scoped to
that opaque group, entry, role, and expiry so ordinary record operations do not
repeat the full proof. The token contains no account identifier and cannot be
used in another group or after the underlying credential expires.

One random group master secret known only to members derives the opaque group
identifier, group-specific identifier-encryption parameters, metadata keys,
and public proof parameters. Identifier encryption is deterministic only
within one group, allowing a client to reconstruct its own entry and the
service to reject duplicates, while remaining unlinkable across groups. Group
attributes are protected with authenticated encryption. Revisions are ordered
and rollback-protected so the service provides one canonical encrypted state
without becoming a trusted source of plaintext membership.

The cryptographic boundary includes prime-order Ristretto255 algebra,
group-specific ElGamal-like verifiable identifier encryption, an algebraic-MAC
keyed-verification anonymous credential, randomized credential presentation,
generalized Schnorr proofs, a complete Fiat-Shamir transcript, strict domain
separation, canonical serialization, expiry, and replay binding. Existing
prototype primitives are not production dependencies until their equations,
transcripts, adversarial tests, independent vectors, and external audit are
complete. In particular, successful tests must prove decryption and knowledge;
they must never accept broken encryption or a proof whose challenge omits its
commitments.

MLS remains responsible for group key agreement, epochs, forward secrecy, and
cryptographic Add and Remove. The encrypted canonical roster describes logical
account membership and authorization; each active account device is still a
separate MLS leaf. Every membership mutation binds one authorized canonical
revision to the corresponding MLS proposal or Commit, and clients reject
server forks, rollbacks, or roster changes that are not reflected in valid MLS
state. The private-group service cannot silently add a decrypting member.

Account deletion stops credential renewal, so private-group access ends within
the deliberately short credential lifetime; it does not pretend to remove an
MLS leaf immediately. Members that decrypt a deleted account in a roster
display it as deleted and complete removal through ordinary MLS Remove Commits.
A private-group service cannot enumerate all groups for one account or globally
edit them on account deletion.

This plan hides the persistent group social graph from the group-state service.
It does not claim network anonymity. The relay may still see exact recipients
of a particular delivery, and group-state access still exposes IP, timing,
volume, cardinality, and opaque-entry metadata unless separate routing,
padding, proxy, PIR, ORAM, or mix-network work is added later.

## How we know it is done

- The service stores canonical encrypted group records and cannot read member
  account identifiers, attributes, titles, or profile data.
- The same account has unrelated deterministic ciphertexts in different
  groups, while duplicate membership is detectable inside one group.
- A randomized, expiry-bound presentation proves possession of a valid account
  credential matching an encrypted member entry without revealing or globally
  linking that account.
- A presentation-derived access token is short-lived, group- and role-scoped,
  unlinkable to the account identifier, and useless after credential expiry.
- Fixed roles on opaque entries let the service enforce group access control
  without learning which account holds a role.
- Group record revisions have authenticated ordering, fork detection, rollback
  protection, strict validation, replay protection, and bounded storage.
- The algebraic MAC, verifiable encryption, Schnorr proof system, Fiat-Shamir
  transcript, serialization, and key derivation pass independent positive,
  negative, malleability, forgery, and cross-domain test vectors before an
  external cryptographic review.
- Every logical roster Add or Remove is bound to valid MLS membership state;
  the service cannot grant message decryption by modifying its database.
- Deleting an account stops credential renewal and bounds remaining group-state
  access by the short credential lifetime, while actual cryptographic exclusion
  still occurs through MLS Remove Commits.
- Documentation states the remaining metadata clearly and never describes
  private group state as complete user or network anonymity.
