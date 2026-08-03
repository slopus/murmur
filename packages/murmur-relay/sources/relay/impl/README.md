# Relay implementation

Wake sources bridge successful store commits to process-local long-poll waiters.
SQLite uses direct in-memory dispatch. Postgres listens on a dedicated
connection; publication itself emits `pg_notify` inside the store transaction.

`ephemeralFanout.ts` holds `InProcessEphemeralFanout`, the default in-process
`EphemeralFanout`. It keeps one bounded, drop-oldest queue per stream subscriber:
enqueueing a frame past the frame-count or byte bound discards the oldest frames
and retains a single coalesced `drop` count, `wake` is a single coalesced flag,
and a subscriber's reader parks on a one-slot signal that resolves on enqueue,
close, or a keepalive tick. The producer never awaits the reader, so a stalled
consumer cannot grow relay memory. `subscribe` admits a reader only while both
the process-wide (`maximumConcurrentStreams`) and per-topic
(`maximumStreamsPerTopic`) ceilings allow it, and a rejected subscribe leaves no
topic entry behind.

Retention is also bounded in aggregate. Every subscriber reports the bytes it
starts and stops holding to the fan-out's ledger, including the batch handed to
a reader — `take()` reclassifies those bytes rather than freeing them, and they
are released when the reader comes back — so `maximumTotalStreamQueueBytes` is a
ceiling on what the whole process holds, not just on what is queued. Exceeding
it evicts the oldest frame of the reader at the front of an insertion-ordered
set of backlogged subscribers, which is the one that has been behind longest;
the accounting is two integer updates and a set membership change per enqueue or
drain, with no scanning.
