# Runtime tests

The runtime end-to-end test uses the owned in-process relay implementation. It
covers offline profile exchange, durable direct-message ordering and
deduplication, encrypted blob delivery, and attachment recovery. Failure-mode
coverage includes paginated poison queues, partial multi-relay blob/event
success, retained retry failures, pending-to-sent reconciliation, and
sender-clock-independent history ordering.

MLS coverage creates epoch zero, exchanges one-use KeyPackages through
profiles, joins through Welcome, replays the retained Commit, persists
bidirectional group messages across restart, and retires a removed member while
draining later ciphertext without decryption.

The completion scenario uses three MLS members, applies concurrent document
inserts on two replicas, converges a third replica over the relay, propagates a
tombstone, and then cryptographically removes one editor.

Failure coverage also delays an epoch Commit on one relay while a future-epoch
application arrives first, proving the CLI retains and retries the unacknowledged
delivery after adoption. A quota-edge codec test proves discarded operations
still advance a durable actor sequence and can never cause ID reuse.
