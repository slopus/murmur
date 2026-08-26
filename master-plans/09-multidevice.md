# Account identity and multiple devices

## Destination

Murmur has one stable public account identity and a signed, versioned roster of
independently keyed devices beneath it. Every device has its own secret key,
MLS leaf, KeyPackages, ratchets, durable store, authenticated inbox, and queue
progress. Devices never share MLS sender state or copy a live epoch checkpoint.
The account-key hierarchy and recovery custody must preserve identity
continuity without allowing the routing service to forge a device.

The first device creates the account identity and initial roster. To add a new
device, its Murmur instance presents ephemeral onboarding material, an active
device verifies user intent, and both establish an encrypted provisioning
channel. The active device authorizes a versioned roster update, the new device
proves possession of its own key, and both bind the result to the stable account
identity. Any active device may revoke any other device. Concurrent, replayed,
or forked roster mutations converge under an explicit authenticated ordering
rule rather than server discretion.

Active devices maintain a built-in account synchronization session. Murmur uses
it for roster control, session routing, and the protocol material
needed to introduce fresh device state. Applications receive a typed,
authenticated channel over the same device relationship and may use it to
transfer history, snapshots, backups, domain keys, or other state. Application
history is never implicit Murmur state and is not reconstructed from an
identity key, MLS Welcome, or relay queue. Large application synchronization is
bounded, chunked, resumable, and controlled by the application.

Service groups treat the account as the logical member while MLS
treats every active device as a separate leaf. Once a new device is accepted in
the account roster, Murmur automatically finds every locally known
service-owned session containing that account, creates or obtains
fresh KeyPackages, and durably submits the required MLS Add proposals. The
authenticated epoch committer serializes the resulting Commits, and the new
device receives a separate Welcome for each session. Offline, pending, or
temporarily blocked sessions converge later without blocking application sends.

Device revocation immediately stops new account authorization, token issuance,
publication, and inbox access for that device. Murmur automatically submits
MLS Remove proposals for the revoked device in every known session. Each
session completes cryptographic removal only when its Remove Commit is adopted;
server-side revocation is not presented as an epoch change and cannot erase
plaintext or secrets the device already possessed.

An authorized device can issue a verifiable account tombstone that revokes the
entire roster and authorizes deletion of account admission, routing, endpoint,
pending-queue, and other account-owned server state. Former peers retain the
tombstone against silent reappearance. Every known MLS session still processes
its own Remove Commit. A recovery and complete-revocation authority that works
after every device store is lost is separate from MLS and application history;
its exact custody and encoding remain to be specified before implementation.

Losing a device store loses that device's ratchets, MLS state, queued plaintext,
and application history. Preserving the stable account identity does not
reconstruct them. A replacement joins as fresh authorized device state and
receives new MLS Welcomes from an active device or recovery flow. Relay replay
is never used as recovery.

## How we know it is done

- One stable account identity has a signed, ordered, replay-protected device
  roster whose mutations cannot be forged or forked by the server.
- An active device and a new instance establish an encrypted onboarding
  channel, prove possession of their keys, and authorize the new device without
  exposing secrets to the relay.
- Any active device can revoke another device, and concurrent additions and
  removals have deterministic authenticated resolution.
- Each device has independent KeyPackages, MLS leaves, ratchets, durable state,
  inboxes, and queue progress; sender or epoch state is never shared.
- Active devices synchronize Murmur-owned account state automatically and give
  applications a typed, bounded, resumable channel for their own state.
- Adding a device automatically and durably drives MLS Adds and Welcomes for
  every known service session containing the account, including
  sessions that must finish later after reconnecting.
- Revoking a device stops future server access immediately and automatically
  drives MLS Removes in every known session without claiming retroactive or
  instantaneous cryptographic erasure.
- A verifiable account tombstone revokes all devices, removes account-owned
  server state, remains recognizable to former peers, and triggers ordinary
  MLS removal convergence.
- A lost device returns only with fresh authorized device and MLS state.
  Identity continuity alone never restores protocol state or application
  history.
