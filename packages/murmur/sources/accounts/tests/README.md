# Account tests

Tests exercise strict roster and mutation codecs. Integration coverage restores
one account on a second store, verifies ordinary inbox notification, converges
the new MLS leaf, and removes the device. The same real SQLite relay integration
also proves stale-roster `409` recovery retargets a durable session outbox to a
new device, directory spent notices replenish the one-use pool, rotation
replaces public material, and one last-resort package accepts two independent
Welcomes.
