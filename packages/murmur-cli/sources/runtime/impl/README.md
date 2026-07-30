# Runtime implementation details

This directory contains strict local codecs for account state, direct and group
history, MLS epoch checkpoints, exact group outboxes, pairwise invitations, and
profile relay envelopes. The runtime's top-level control flow stays in the
parent module.

The document codec canonicalizes the bounded core CRDT log and discriminates
document create/mutation messages from ordinary group chat without changing
the MLS or relay wire layers.
