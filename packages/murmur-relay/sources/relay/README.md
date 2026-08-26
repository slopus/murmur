# Relay service

`RelayService` validates signed opaque delivery envelopes, delegates atomic
multicast and queue operations to storage, and coordinates long-poll and stream
wakeups.

```text
signed delivery -> validation -> atomic recipient fanout -> wake
signed read -> authentication -> ordered bounded page
signed acknowledgement -> authentication -> monotonic prefix trim
account-signed deletion -> replay check -> exact owner/session purge
account-signed upload -> current roster device -> durable prekey state
ticket + exact account -> atomic per-device claim -> spent-notice wake
```

Quota policy covers recipient inboxes, senders, ingress principals, and global
pending storage. Expiry pruning is bounded and destructive.

Directory ticket verification is pluggable. The service validates the upload's
account signature and every embedded device-signed spent notice before storage.
