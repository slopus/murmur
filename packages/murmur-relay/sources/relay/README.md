# Relay service

`RelayService` validates signed opaque delivery envelopes, delegates atomic
multicast and queue operations to storage, and coordinates long-poll and stream
wakeups.

```text
signed delivery -> validation -> atomic recipient fanout -> wake
signed read -> authentication -> ordered bounded page
signed acknowledgement -> authentication -> monotonic prefix trim
```

Quota policy covers recipient inboxes, senders, ingress principals, and global
pending storage. Expiry pruning is bounded and destructive.
