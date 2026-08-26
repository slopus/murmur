# Murmur as a minimal stateful MLS library

## Vision

Murmur is small. It is a stateful library that does three things:

1. Get another account's keys by its public identity key (one-off prekeys
   claimed through the relay's identity directory) and start communicating
   with that account.
2. Keep its own prekeys uploaded, synchronized, and rotated at the relay.
3. Run MLS sessions with a few roles: who can change members, who can send,
   and who owns the session. The owner can delete it.

There are no contacts, no invitations, no profiles, no anonymized group
state, and no server-stored history. Murmur is for sessions; everything else
is secondary and belongs to the application. A two-person interaction and a
many-person interaction use the same MLS group primitive. Chat, documents,
and other application protocols live in optional typed synchronization
services registered on the client, not in the relay or the MLS engine.

It ships as the browser-safe and Node.js-compatible `@slopus/murmur` library.
The relay is internal infrastructure: a disposable delivery buffer plus the
identity directory, never session state or history.

There is no backward compatibility. Old APIs, wire formats, storage schemas,
and relay schemas are deleted, not migrated or decoded.

## Identity and the account secret

One account is one Ed25519 identity key. The application user protects it
with a 1Password-like account secret: a strong generated string combined
with a user password. That secret encrypts the identity key, the backup key,
and whatever other root material exists, and the encrypted blob is persisted
somewhere the application chooses. Adding a new device is restoring this
secret — copying it from the phone or wherever it lives — not a provisioning
ceremony, a signed device roster, or a per-device key hierarchy.

Every running device that holds the restored identity is the same account.
Session state is never replicated between devices: ratchets are single-writer,
so each running client keeps its own MLS leaves, durable store, and inbox.
Losing a device's store loses that device's session state and is recovered by
fresh bootstraps, never by copying ratchets.

## The relay

The relay stores exactly two kinds of data: encrypted deliveries that remain
unacknowledged and unexpired, and the identity directory of published
prekeys. Everything it stores is linked to the owning account and session, so
deleting an account or deleting a session can remove everything that belongs
to it. It stores no history, snapshots, retained events, invitation caches,
anonymous topics, or MLS state, and it never interprets encrypted contents.

The server is honest but not trusted: we rely on it to perform the protocol
correctly — it may hold authoritative MLS-adjacent state and additively
enforce delivery completeness and basic roles — but it can never decrypt
anything, and every member still verifies everything locally. A server that
stops servicing something is an accepted, unavoidable failure mode.

Admission, device, sender, recipient, timing, queue, and fanout metadata are
an accepted tradeoff. Murmur promises encrypted contents, not anonymous
routing.

## The layers, in order

1. **Account.** One identity key, wrapped by the account secret, restored
   onto any device.
2. **Directory.** Upload, synchronize, and rotate one-off prekeys plus one
   multi-use last-resort prekey; claim a target account's prekeys by its
   exact identity key, gated by tickets from the authentication server.
3. **Bootstrap.** Create an MLS session from claimed prekeys and deliver its
   Welcome to the recipient's authenticated queue; the recipient persists it
   as pending and later activates or ignores it.
4. **MLS sessions with roles.** Opaque descriptors, opaque events, membership
   changes, and role enforcement — owner, admins, member policies — through
   one primitive for two or more members. The owner can delete the session,
   which removes its relay state.
5. **Synchronization services.** Optional independent typed services that
   claim sessions and receive their updates.

## How we know it is done

- `@slopus/murmur` opens with a relay and application-supplied transactional
  persistence in a browser or Node.js process.
- The account secret — strong generated string plus password — encrypts and
  restores the identity root; restoring it on a new device is the entire
  multidevice story.
- Knowing an identity key and holding a ticket is sufficient to claim prekeys
  and start a session or group with that account. No contact, invitation, or
  profile machinery exists anywhere in the library.
- Prekey pools stay stocked and rotated automatically; exhaustion falls back
  to the multi-use last-resort prekey.
- Sessions enforce owner, admin, membership, and send roles identically at
  every member, and the owner can delete the session including its relay
  state.
- Every session operation works offline from durable local state; sends never
  wait on connectivity, peer presence, or staged Commits.
- Queue processing survives redelivery and acknowledges only after durably
  recording progress and outcome.
- Deleting an account removes its directory entries, queues, and other
  account-linked relay state; deleting a session removes that session's.
- No contacts, invitation bundles, anonymized group state, server history, or
  backward-compatibility machinery remains in the codebase.
