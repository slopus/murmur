# Account secret and devices

## Destination

One account is one identity key, and the multidevice story is restoring that
key, not authorizing new keys. There is no signed device roster, no
provisioning ceremony, and no per-device key hierarchy.

The account secret works like 1Password: a strong generated string combined
with the user's password. Together they encrypt the identity key, the backup
key, and any other root material. The encrypted blob is persisted somewhere
the application chooses. A client needs the password and the generated
string to unlock it; the generated string is high-entropy, so the blob
withstands offline guessing even where it is stored.

Adding a new device is restoring this secret — copying it from the phone or
wherever it lives. Whoever holds the restored secret is the account. There is
no server-side reset path: losing the secret is final, and no server can
recover or rotate it on the user's behalf.

Devices still exist as entities beneath the account. Each device has its own
inbox, MLS leaves, ratchets, durable store, and queue progress — session
state is never replicated between devices, because ratchets are
single-writer. The account has a device roster: a restored device registers
itself in it by proving possession of the identity key, which is the entire
authorization — no active device approves it and no provisioning ceremony
runs. Any device may remove another device or itself from the roster. The
relay holds the current roster as account-linked state so senders can fetch
it and target every device.

Restoring the identity restores reachability, not state. A restored device
re-enters sessions through fresh bootstraps: peers observe the roster change
and add its new leaf, re-encrypting for the new device. Murmur never copies,
merges, or reconstructs ratchet state from the identity key, a backup, or
the relay.

Application history is never implicit Murmur state. Applications that want
history on a restored device move it themselves through their own storage or
their own protocols.

## How we know it is done

- A strong generated secret plus the user password encrypts the identity root
  into a blob the application can persist anywhere; unlocking requires both.
- Restoring the blob on a new device yields the same account: the device
  registers itself in the roster by proving possession of the identity key,
  the directory serves prekeys under the same identity, and peers verify the
  same identity — with no approval ceremony.
- The relay serves each account's current device roster, and senders can
  fetch it to target every device.
- No server-side recovery, reset, or rotation of the account secret exists.
- Session state is never shared or restored across devices; a restored device
  re-enters sessions only through fresh bootstraps and peer re-encryption
  for its new leaf.
- No provisioning handshake, roster approval ceremony, or per-device key
  hierarchy remains in the codebase.
