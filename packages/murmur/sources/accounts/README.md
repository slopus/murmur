# Accounts

The account domain links multiple device identities under one account signing
root. It owns signed roster revisions, device credentials, provisioning
transcripts, account synchronization packets, convergence jobs, and lifecycle
records.

## Provisioning

A fresh device creates short-lived link material containing an MLS KeyPackage.
An active device verifies and authorizes the request, signs the next roster,
adds the device to the internal account MLS session, and publishes an encrypted
provisioning envelope to the new device's identity queue.

The new device adopts the account root, roster, and account-authorized device
credential atomically. The application transports only the link request; queue
delivery carries the secret envelope.

## Roster convergence

Roster revisions are monotonic and signed by active devices. A revision can add,
reset, or revoke one device. Murmur derives durable convergence jobs and drives
the matching MLS additions and removals across known sessions.

Public session views expose account identities even when several device leaves
participate internally. Dormancy reporting identifies active sibling devices
without authenticated activity for six months; revocation remains explicit.
