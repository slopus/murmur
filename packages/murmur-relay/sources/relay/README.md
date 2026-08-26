# Relay service

`RelayService` validates signed opaque delivery envelopes, delegates atomic
multicast and queue operations to storage, and coordinates long-poll and stream
wakeups.

```text
direct delivery -> validation -> exact recipient fanout -> wake
session delivery -> member/role/epoch checks -> roster-derived fanout -> wake
signed read -> authentication -> ordered bounded page
signed acknowledgement -> authentication -> monotonic prefix trim
account-signed session deletion -> replay check -> exact owner/session purge
account-signed account deletion -> replay check -> complete ownership cascade
account-signed upload -> current roster device -> durable prekey state
ticket + exact account -> atomic per-device claim -> spent-notice wake
```

Quota policy covers recipient inboxes, senders, ingress principals, and global
pending storage. Expiry pruning is bounded and destructive.

Directory ticket verification is pluggable. The service validates the upload's
account signature and every embedded device-signed spent notice before storage.
For ordinary device publication it also proves the signed sender account owns
the active device, preventing forged cleanup ownership.

Relay-visible creation and Commit summaries advance persisted session state in
the same transaction as queue insertion. A stale or concurrent losing epoch is
rejected, application send policy is enforced, and incomplete current-device
coverage returns the authoritative rosters needed for MLS leaf convergence.
