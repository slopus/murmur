# Delivery

Browser-safe relay transport and the durable identity-inbox processor.

```text
signed page read --\
                    +-> queued ciphertext -> store transaction -> signed ack
signed SSE stream -/                         | buffer/rejection |
                                              | cursor advance   |
                                              +------------------+
```

The SSE path carries the exact queued delivery and UUIDv7 event ID, applies
stream backpressure, and processes one record at a time. It is not a wake-only
channel. Reconnect uses a freshly signed request after the durable local cursor,
so anything committed but not acknowledged may be replayed safely.

The processor never acknowledges before the protocol state plus buffered update
or terminal rejection and cursor commit atomically. A crash after the local
commit causes a harmless acknowledgement retry. Consumer callbacks run later
through the identity-wide session sync loop and never receive this transaction.
Relay queues are delivery buffers, never application history. Sender-scoped
delivery IDs remain replay-protected until their signed expiration; the bounded
replay index applies backpressure instead of evicting live protection. At
exact-index capacity, new IDs are terminally rejected into a fixed-size,
time-bucketed probabilistic replay filter. Its only error mode is a
false-positive rejection; it never exposes a probable replay to application
code or blocks the queue.

Replay expiry and overflow epochs advance from the relay-assigned UUIDv7 event
time. Inbox ordering makes that clock nondecreasing; its magnitude must also
fall within the local 90-day retention horizon plus configured clock skew.
An implausible timestamp rejects the page without changing durable state.
Murmur enforces the relay profile's 90-day hard remaining-TTL bound, but a
validly signed TTL-policy failure is not added to the terminal filter.
Structurally valid invalid IDs enter a bounded rotating terminal filter, so
repeated invalid deliveries avoid repeated cryptographic work without making
its false-positive rate grow for the lifetime of the store. Saturation can only
reject additional traffic.

An oversized head response is a relay-directed terminal skip: the processor
persists `delivery_too_large`, advances its cursor, and acknowledges without
seeing the ciphertext. A stale local backup behind the relay's acknowledged
prefix instead throws `InboxStateRollbackError`; it cannot be repaired by
skipping missing MLS state.
