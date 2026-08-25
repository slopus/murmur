# Accounts and devices

This module defines the stable account-signing identity and its independently
keyed device roster. The account key signs roster state only. Device keys sign
delivery, MLS, and provisioning traffic and own independent inboxes and
ratchets.

```text
account signing key
        |
        +-- signed roster revision
                |
                +-- active device A -> inbox + MLS leaves
                +-- active device B -> inbox + MLS leaves
                `-- revoked device C
```

Roster revisions name their parent hash. Authenticated siblings are ordered by
their exact SHA-256 digest, so every participant presented with the same forks
selects the same winner without relay discretion. Provisioning follows the
Signal linking shape: a new device presents a short-lived URI containing an
ephemeral key and device proof, and an active device returns an encrypted,
transcript-bound account authorization.

## Structure

- `index.ts` — the export surface documented below.
- `types.ts` — roster, provisioning, and lifecycle-event interfaces.
- `impl/deviceRosterCodec.ts` — signed roster construction and verification.
- `impl/deviceProvisioning.ts` — the encrypted device-linking handshake.
- `impl/accountRecords.ts` — durable roster observation, lifecycle events,
  and MLS convergence jobs.
- `impl/accountSyncCodec.ts` — the built-in account-sync session protocol.
- `tests/` — roster/provisioning unit tests plus the multidevice messenger
  integration test.

## Exports

### Device roster (`impl/deviceRosterCodec.ts`)

The roster is the account's authoritative, replay-protected device list. Each
revision is account-signed and author-device-countersigned and names its
parent revision hash, forming a verifiable chain the server cannot forge,
fork, or roll back.

- `createInitialDeviceRoster(account, device, issuedAt, mutationId):
MurmurDeviceRoster` — revision 1: the founding device authorizes itself.
- `addDeviceToRoster(previous, account, authorDevice, deviceKey, issuedAt,
mutationId): MurmurDeviceRoster` — signed child revision adding one active
  device; the author must itself be active in `previous`.
- `revokeDeviceFromRoster(previous, account, authorDevice, deviceKey,
issuedAt, mutationId): MurmurDeviceRoster` — signed child revision marking
  one device revoked; a device cannot revoke itself.
- `verifyDeviceRoster(roster): boolean` — canonical shape plus both
  signatures.
- `isActiveDevice(roster, deviceKey): boolean` — membership check.
- `serializeDeviceRoster(roster)` / `parseDeviceRoster(value)` — strict wire
  codec; parsing re-verifies signatures.
- `deviceRosterHash(roster): Uint8Array` — the SHA-256 revision hash used for
  parent links and fork ordering.
- `selectDeviceRosterChild(current, candidates): MurmurDeviceRoster` —
  deterministic fork resolution: among authenticated siblings of the same
  parent, the larger digest wins for every observer.
- `encodeDeviceCredential(roster, deviceKey): Uint8Array` — the
  account-signed MLS BasicCredential payload binding one device leaf to the
  account ("account X authorized device Y at revision N").
- `decodeDeviceCredential(value): MurmurDeviceCredential` — parse and verify
  that credential, including the account authorization signature.

### Provisioning (`impl/deviceProvisioning.ts`)

The Signal-style linking handshake. All artifacts are short-lived (5 minutes),
transcript-bound, and replay-protected.

- `createDeviceLinkMaterial(device, keyPackage, now?, ttlMilliseconds?):
MurmurDeviceLinkMaterial` — new device builds the signed link request (its
  key, an ephemeral X25519 key, its MLS KeyPackage, a possession proof) and
  keeps the ephemeral secret.
- `authorizeDeviceProvisioning(authorization): { envelope, roster }` — active
  device verifies the request, signs the next roster revision, and returns an
  AES-GCM envelope encrypted to the new device's ephemeral key carrying the
  account signing root and the new roster. The request hash is bound into the
  AAD so an envelope cannot answer a different request.
- `completeDeviceProvisioning(material, envelope, now?):
MurmurProvisionedAccount` — new device authenticates and decrypts the
  envelope and checks the roster actually authorizes it.
- `serializeDeviceLinkRequest` / `parseDeviceLinkRequest` — out-of-band codec
  for the request (what an application renders as a QR code); parsing
  enforces expiry and the possession proof.
- `serializeProvisioningEnvelope` / `parseProvisioningEnvelope` — out-of-band
  codec for the encrypted response.
- `serializeDeviceLinkMaterial` / `parseDeviceLinkMaterial` — durable storage
  codec for the pending link, including the ephemeral secret.

### Durable records and convergence (`impl/accountRecords.ts`)

Where authenticated roster updates become durable local effects: lifecycle
events for callbacks and MLS membership jobs for automatic convergence.

- `observeDeviceRoster(transaction, ownAccount, eventId, senderAccount,
senderDevice, rosterBytes, admission?)` — validate one roster transition
  (sender must be an active device of that account; revisions must chain or
  win fork ordering), persist it, record added/revoked events, and queue
  convergence jobs. Used for both own-account and contact rosters.
- `accountConvergenceJobs(store): readonly AccountConvergenceJob[]` — read
  the bounded queue of pending MLS Add/Remove work.
- `deleteAccountConvergenceJob(store, key)` — remove one completed job.
- `recordAccountEvent(transaction, record)` — idempotently persist one
  lifecycle event.
- `prepareAccountEvents(store): PreparedAccountEvents` — read one immutable
  batch of pending `onDeviceAdded` / `onDeviceRevoked` /
  `onContactRosterChanged` notifications.
- `deletePreparedAccountEvents(transaction, prepared)` — drain the batch only
  after every callback resolved.
- Store-key constants: `ACCOUNT_ROSTER_KEY`, `ACCOUNT_PEER_ROSTER_PREFIX`,
  `ACCOUNT_EVENT_PREFIX`, `ACCOUNT_CONVERGENCE_PREFIX`.

### Account-sync session protocol (`impl/accountSyncCodec.ts`)

The built-in MLS session between the devices of one account, used to carry
roster updates and admission KeyPackages; never surfaced to applications.

- `accountSyncSessionDescriptor(): Uint8Array` — the fixed descriptor.
- `isAccountSyncSessionDescriptor(value): boolean` — exact match check.
- `encodeAccountSyncPacket(packet)` / `decodeAccountSyncPacket(value)` —
  strict canonical codec for `roster` and `admission` packets.

### Types (`types.ts`)

`MurmurDeviceRoster`, `MurmurDeviceRosterEntry`, `MurmurDeviceCredential`,
`MurmurDeviceLinkRequest`, `MurmurDeviceLinkMaterial`,
`MurmurDeviceProvisioningAuthorization`, `MurmurDeviceProvisioningEnvelope`,
`MurmurProvisionedAccount`, `MurmurDeviceAdded`, `MurmurDeviceRevoked`,
`MurmurContactRosterChanged`.

This module deliberately knows nothing about the private-group mathematics;
the only place the two meet is `sources/privateGroupState`.
