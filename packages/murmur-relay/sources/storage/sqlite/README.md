# SQLite store

The SQLite backend uses `node:sqlite`, WAL, foreign keys, and `BEGIN IMMEDIATE`
for every publish or prune transaction. Because the synchronous transaction
contains no JavaScript suspension point, conflict checks, sequence allocation,
state mutation, and event insertion are one indivisible operation.

Topic deletion cascades to snapshots, list elements, and retained events. Small
event ID receipts live until their topic is deleted, so pruning the event body
never weakens idempotency. Blob bytes are not stored in SQLite.
